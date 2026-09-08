//! Authenticated binary streams with bounded, directly pushed peer delivery.
use super::*;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use serde_json::{Value, json};
use std::{collections::HashMap, time::Duration};
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Command {
    id: u64,
    handle: u32,
    game_id: Option<String>,
    body: Option<Value>,
    ack: Option<DurableAck>,
}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct DurableAck {epoch:String,after:u64}
struct Subscription {
    game_id: String,
    request: routes::ExchangeRequest,
    delivered: u64,
    joined: bool,
}
pub(super) async fn upgrade(
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.max_message_size(MAX_JSON_BODY_BYTES)
        .max_frame_size(MAX_JSON_BODY_BYTES)
        .on_upgrade(move |socket| serve(socket, state))
}
async fn send(socket: &mut WebSocket, value: Value, blobs: Vec<Vec<u8>>) -> bool {
    match wire::encode(value, blobs) {
        Ok(bytes) => socket.send(Message::Binary(bytes.into())).await.is_ok(),
        Err(_) => false,
    }
}
async fn serve(mut socket: WebSocket, state: AppState) {
    let mut rooms: HashMap<u32, Subscription> = HashMap::new();
    let mut changes = state.changes.subscribe();
    let mut ping = tokio::time::interval(Duration::from_secs(25));
    let mut last_seen = tokio::time::Instant::now();
    loop {
        tokio::select! {
            incoming=socket.recv()=>{
                let Some(Ok(message))=incoming else{break};last_seen=tokio::time::Instant::now();
                match message {
                    Message::Binary(bytes)=>{
                        let Ok((value,blobs))=wire::decode(&bytes) else{break};
                        let Ok(command)=serde_json::from_value::<Command>(value) else{break};
                        if let Some(ack)=command.ack {
                            if command.body.is_some() || command.game_id.is_some() {break;}
                            let Some(sub)=rooms.get_mut(&command.handle) else{break};
                            if sub.request.epoch.as_ref()!=Some(&ack.epoch) || ack.after>sub.delivered {break;}
                            // Only a browser's persisted cursor can release delivery.
                            // Acknowledge without making it wait for an empty response.
                            if ack.after<=sub.request.after {continue;}
                            let mut request=sub.request.clone();request.after=ack.after;
                            match routes::exchange_binary(state.clone(),sub.game_id.clone(),request.clone(),Some(vec![]),Some((ack.epoch.clone(),sub.delivered))).await {
                                Ok(response)=>{
                                    sub.request=request;
                                    if response.page.next_cursor>sub.delivered || response.page.joined!=sub.joined {
                                        sub.delivered=response.page.next_cursor;sub.joined=response.page.joined;
                                        let (page,blobs)=wire::page(response.page);
                                        if !send(&mut socket,json!({"push":command.handle,"value":page}),blobs).await{break;}
                                    }
                                },
                                Err(_)=>break,
                            }
                            continue;
                        }
                        let Some(mut body)=command.body else {rooms.remove(&command.handle);if !send(&mut socket,json!({"id":command.id,"value":null}),vec![]).await{break;}continue;};
                        let game=if let Some(sub)=rooms.get(&command.handle) {
                            if command.game_id.is_some() || ["playerToken","inviteSecret","sender"].iter().any(|key|body.get(key).is_some()){break;}
                            body["playerToken"]=json!(sub.request.player_token);body["inviteSecret"]=json!(sub.request.invite_secret);body["sender"]=json!(sub.request.sender);sub.game_id.clone()
                        } else {if rooms.len()>=128 {break;}let Some(game)=command.game_id else{break};game};
                        let Ok(mut request)=serde_json::from_value::<routes::ExchangeRequest>(body) else{break};
                        let delivered=rooms.get(&command.handle).and_then(|s|s.request.epoch.clone().map(|epoch|(epoch,s.delivered)));
                        let result=routes::exchange_binary(state.clone(),game.clone(),request.clone(),Some(blobs),delivered).await;
                        match result {
                            Ok(response)=>{
                                let cursor=response.page.next_cursor;let epoch=response.page.epoch.clone();let joined=response.page.joined;
                                request.messages.clear();
                                if request.epoch.as_ref()!=Some(&epoch) {request.after=0;}
                                request.epoch=Some(epoch);
                                // The request cursor is durable; delivered may be ahead, but is never used as an ACK.
                                let delivered=rooms.get(&command.handle).filter(|s|s.request.epoch==request.epoch).map_or(cursor,|s|s.delivered.max(cursor));
                                rooms.insert(command.handle,Subscription{game_id:game,request,delivered,joined});
                                let (mut page,blobs)=wire::page(response.page);page["accepted"]=json!(response.accepted);
                                if !send(&mut socket,json!({"id":command.id,"value":page}),blobs).await{break;}
                            },
                            Err(error)=>{if !send(&mut socket,json!({"id":command.id,"error":{"status":error.status.as_u16(),"message":error.message}}),vec![]).await{break;}},
                        }
                    },
                    Message::Ping(_) | Message::Pong(_)=>{},
                    _=>break,
                }
            },
            change=changes.recv()=>{
                let changed=match change {Ok(room)=>Some(encode_hex(room)),Err(tokio::sync::broadcast::error::RecvError::Lagged(_))=>None,Err(_)=>break};
                for (&handle,sub) in &mut rooms {
                    if changed.as_ref().is_some_and(|id|id!=&sub.game_id) {continue;}
                    // At most one unacknowledged page per subscription. A durable ACK or exchange drains the next page.
                    if sub.delivered>sub.request.after {continue;}
                    let mut request=sub.request.clone();request.after=sub.delivered;
                    match routes::push_room(state.clone(),sub.game_id.clone(),request).await {
                        Ok(page)=>{
                            if page.next_cursor==sub.delivered && page.joined==sub.joined {continue;}
                            sub.delivered=page.next_cursor;sub.joined=page.joined;
                            let (page,blobs)=wire::page(page);
                            if !send(&mut socket,json!({"push":handle,"value":page}),blobs).await{return;}
                        },
                        Err(_)=>{if !send(&mut socket,json!({"resync":handle}),vec![]).await{return;}},
                    }
                }
            },
            _=ping.tick()=>{
                if last_seen.elapsed()>Duration::from_secs(60){break;}
                if socket.send(Message::Ping(Vec::new().into())).await.is_err(){break;}
            }
        }
    }
}

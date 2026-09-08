import { formatBitcoinAmount as money } from "../ui/bitcoin-amount.js";
const $ = (id) => document.getElementById(id);
const ranks = ["2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K", "A"];
const suits = ["♣", "♦", "♥", "♠"];

export function setStatus(headline, detail, visible = true) {
  if (visible) highlightTurn(null);
  $("table-phase").textContent = headline;
  $("table-phase").classList.toggle("busy", headline.endsWith("…"));
  $("table-detail").textContent = detail;
  $("table-message").classList.toggle("hidden", !visible);
}

export function renderCard(element, id) {
    const rank = ranks[Math.floor(id / 4)];
    const suit = suits[id % 4];
    const label = document.createElement("span");
    const rankNode = document.createElement("span");
    const suitNode = document.createElement("span");
    label.className = `card-label${rank === "10" ? " wide-rank" : ""}`;
    rankNode.className = "card-rank";
    suitNode.className = "card-suit";
    rankNode.textContent = rank;
    suitNode.textContent = suit;
    label.append(rankNode, suitNode);
    element.replaceChildren(label);
    element.dataset.suit = ["clubs", "diamonds", "hearts", "spades"][id % 4];
    element.setAttribute("aria-label", `${rank} ${suit}`);
    element.classList.remove("empty");
    element.classList.add("dealt");
    element.classList.toggle("red", id % 4 === 1 || id % 4 === 2);
  }

// Denominations are shared by both seats and the pot.
export function renderChipStack(element, amount) {
  amount = Number.isSafeInteger(amount) && amount > 0 ? amount : 0;
  if (element.dataset.amount === String(amount)) return;
  element.dataset.amount = String(amount);
  const chips = [];
  for (const [value, color, edge] of [
    [10000, '#c8ac58', '#76612c'], [2500, '#7956a6', '#422c60'],
    [500, '#387fbc', '#19466a'], [100, '#b96b26', '#603414'],
    [25, '#388565', '#194c37'], [5, '#b84b50', '#65272a'], [1, '#b4b9af', '#62695d'],
  ]) {
    const count = Math.floor(amount / value);
    amount %= value;
    for (let i = 0; i < count; i++) {
      const chip = document.createElement('i');
      chip.dataset.denomination = String(value);
      chip.style.background = color;
      chip.style.boxShadow = `0 3px 0 ${edge}, 0 4px 5px #0006`;
      chips.push(chip);
    }
  }
  chips.forEach((chip, i) => { chip.style.bottom = `${i * Math.min(5, 18 / Math.max(1, chips.length - 1))}px`; });
  element.replaceChildren(...chips);
}

export function collectedPot(total, roundBets = [0, 0]) {
  return Math.max(0, total - roundBets.reduce((sum, amount) => sum + amount, 0));
}

export function renderPot(total, roundBets) {
  const amount = collectedPot(total, roundBets);
  $("game-pot").textContent = money(amount);
  const chips = document.querySelector(".pot-chips");
  renderChipStack(chips, amount);
  chips.style.visibility = amount > 0 ? "visible" : "hidden";
  document.querySelector(".pot-display").style.visibility = amount > 0 ? "visible" : "hidden";
}

export function renderBalances(stacks, localRole, pot, roundBets = [0, 0], confirmedBets = roundBets) {
    $("local-stack").textContent = money(stacks[localRole]);
    $("opponent-stack").textContent = money(stacks[1 - localRole]);
    renderPot(pot, confirmedBets);
    for (const [seat, role] of [["local", localRole], ["opponent", 1 - localRole]]) {
      const amount = roundBets[role];
      renderChipStack($(`${seat}-bet`).querySelector(".chip-stack"), amount);
      $(`${seat}-bet`).classList.toggle("hidden", amount <= 0);
      $(`${seat}-bet-amount`).textContent = money(amount);
      $(`${seat}-bet`).setAttribute("aria-label", `${seat === "local" ? "Your" : "Opponent’s"} bet this round: ${money(amount)}`);
    }
  }

export function highlightTurn(seat) {
  for (const name of ['local', 'opponent']) {
    const element = document.querySelector(`.seat-${name}`);
    element?.classList.toggle('active-turn', name === seat);
    element?.setAttribute('aria-label', `${name === 'local' ? 'You' : 'Opponent'}${name === seat ? ' — to act' : ''}`);
  }
}

let lastChips;
export function animateChips({ hand, bets, pot, terminal = false, winner = null }) {
  const table = document.querySelector('.poker-table');
  const center = document.querySelector('.pot-chips');
  if (lastChips?.hand !== hand) table.querySelectorAll('.flying-chips').forEach(chip => chip.remove());
  const fly = (from, to, delay = 0, amount) => {
    if (!from || !to || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const bounds = table.getBoundingClientRect(), a = from.getBoundingClientRect(), b = to.getBoundingClientRect();
    const chip = (from.matches(".chip-stack") ? from : from.querySelector(".chip-stack") ?? center).cloneNode(true);
    if (amount !== undefined) renderChipStack(chip, amount);
    chip.removeAttribute('id');
    chip.className = 'chip-stack flying-chips';
    chip.style.left = `${a.left + a.width / 2 - bounds.left - table.clientLeft - 16}px`;
    chip.style.top = `${a.top + a.height / 2 - bounds.top - table.clientTop - 14}px`;
    table.append(chip);
    const animation = chip.animate([
      {transform:'translate(0,0)',opacity:1},
      {transform:`translate(${b.left+b.width/2-a.left-a.width/2}px,${b.top+b.height/2-a.top-a.height/2}px)`,opacity:0.2},
    ], {duration:450,delay,easing:'cubic-bezier(.22,.7,.3,1)',fill:'both'});
    animation.finished.catch(()=>{}).finally(()=>chip.remove());
  };
  if (lastChips?.hand === hand) {
    if (terminal && !lastChips.terminal && lastChips.pot > 0) {
      // End any in-flight collection before awarding the chips. Every visible
      // source now moves toward the winner, never back to a losing seat.
      table.querySelectorAll('.flying-chips').forEach(chip => { chip.getAnimations().forEach(animation => animation.cancel()); chip.remove(); });
      const destinations = winner === null ? ['local','opponent'] : [winner];
      const sources = [[center, collectedPot(lastChips.pot, lastChips.bets)],
        ...['local','opponent'].map((seat,i) => [$(`${seat}-bet`).querySelector('.chip-stack'), lastChips.bets[i]])];
      for (const [source, amount] of sources) {
        if (amount <= 0) continue;
        for (const seat of destinations) fly(source, document.querySelector(`.seat-${seat}`), 0, amount / destinations.length);
      }
    } else if (!terminal) {
      const collected = bets.every(n=>n===0) && lastChips.bets.some(n=>n>0);
      if (collected) for (const [i,seat] of ['local','opponent'].entries()) {
        if (lastChips.bets[i]>0) fly($(`${seat}-bet`).querySelector('.chip-stack'),center,0,lastChips.bets[i]);
      }
    }
  }
  renderPot(pot, bets);
  lastChips = {hand,bets:[...bets],pot,terminal};
}


export function playerName(value) {
  return typeof value === 'string' ? Array.from(value.replace(/[\p{Cc}\p{Cf}]/gu, '').trim().replace(/\s+/gu, ' ')).slice(0,24).join('') : '';
}
export function savedPlayerName() {
  try { return playerName(localStorage.getItem('poker-player-name')); } catch { return ''; }
}
export function renderPlayerNames(local, opponent) {
  local = playerName(local); opponent = playerName(opponent);
  for (const [seat,name,fallback] of [['local',local,'You'],['opponent',opponent,'Opponent']]) {
    const label = $(`${seat}-name`);
    label.textContent = name || fallback;
    label.title = name || fallback;
    $(`${seat}-avatar`).textContent = name ? Array.from(name)[0].toLocaleUpperCase() : seat === 'local' ? 'Y' : '?';
  }
}
if (typeof document !== 'undefined') {
  const form = $('nickname-form');
  if (form) {
    if (!$('nickname').value) $('nickname').value = savedPlayerName();
    form.addEventListener('submit', event => {
      event.preventDefault();
      const name = playerName($('nickname').value);
      if (!name) { $('nickname').setCustomValidity('Enter a nickname.'); $('nickname').reportValidity(); return; }
      $('nickname').value = name;
      try { localStorage.setItem('poker-player-name', name); } catch {}
      document.body.classList.remove('nickname-onboarding');
      window.dispatchEvent(new Event('nickname-ready'));
    });
    $('nickname').addEventListener('input', () => $('nickname').setCustomValidity(''));
    form.querySelector('button').disabled = false;
  }
}

const $ = (id) => document.getElementById(id);
const money = (value) => `₿${Number(value).toLocaleString("en-US")}`;
const ranks = ["2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K", "A"];
const suits = ["♣", "♦", "♥", "♠"];

export function setStatus(headline, detail, visible = true) {
  $("table-phase").textContent = headline;
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
    element.setAttribute("aria-label", `${rank} ${suit}`);
    element.classList.remove("empty");
    element.classList.add("dealt");
    element.classList.toggle("red", id % 4 === 1 || id % 4 === 2);
  }

export function renderBalances(stacks, localRole, pot) {
    $("local-stack").textContent = `Stack · ${money(stacks[localRole])}`;
    $("opponent-stack").textContent = `Stack · ${money(stacks[1 - localRole])}`;
    $("game-pot").textContent = money(pot);
  }

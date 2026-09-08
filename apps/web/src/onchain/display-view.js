// Add display metadata only when both engines describe the same confirmed state.
// Legal actions and all signing decisions remain owned by the saved game's engine.
export function enrichDisplayView(view, checked) {
  for (const key of ["tip", "node", "role", "terminal", "betting", "pot", "stacks"]) {
    if (JSON.stringify(view[key]) !== JSON.stringify(checked[key])) return view;
  }
  const enriched = { ...view };
  for (const key of ["roundBets", "revealing", "opponentCards", "nextStacks"]) {
    if (view[key] === undefined && checked[key] !== undefined) enriched[key] = checked[key];
  }
  if (view.actions) enriched.actions = view.actions.map(action => {
    const match = checked.actions?.find(candidate => candidate.index === action.index && candidate.kind === action.kind);
    return action.betAmount === undefined && match?.betAmount != null ? { ...action, betAmount: match.betAmount } : action;
  });
  return enriched;
}

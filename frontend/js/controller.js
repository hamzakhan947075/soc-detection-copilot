// Small mutable indirection so tab modules can trigger a re-render or tab
// switch without creating circular imports with app.js (which owns the
// actual render loop and imports every tab module).
export const controller = {
  refresh: () => {},
  goTo: (_tabId) => {},
};

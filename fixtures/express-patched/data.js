// Seeded throwaway data for the patched Express fixture. Identical to the
// vulnerable fixture's data, so the only difference between the two apps is
// the code that guards it.

const users = {
  'userA-token': { id: 'userA', name: 'Ada Example', role: 'member' },
  'userB-token': { id: 'userB', name: 'Grace Example', role: 'member' },
  'admin-token': { id: 'admin', name: 'Root Example', role: 'admin' },
};

const orders = [
  {
    id: 90001,
    userId: 'userB',
    item: 'Decoy order for scanner verification',
    total: 4242,
    note: 'VK-CANARY-USERB',
  },
  {
    id: 90002,
    userId: 'userA',
    item: 'Decoy order for scanner verification',
    total: 1111,
    note: 'VK-CANARY-USERA',
  },
];

const profiles = [
  { id: 90001, userId: 'userB', email: 'grace@example.invalid', note: 'VK-CANARY-USERB-PROFILE' },
  { id: 90002, userId: 'userA', email: 'ada@example.invalid', note: 'VK-CANARY-USERA-PROFILE' },
];

module.exports = { users, orders, profiles };

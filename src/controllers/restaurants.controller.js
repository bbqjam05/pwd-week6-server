const restaurantService = require('../services/restaurants.service');
const asyncHandler = require('../utils/asyncHandler');

const normaliseMenu = (menu) => {
  if (!menu) return [];
  if (Array.isArray(menu)) return menu;
  if (typeof menu === 'string') {
    return menu
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean);
  }
  return [];
};

exports.getRestaurants = asyncHandler(async (req, res) => {
  const restaurants = await restaurantService.getAllRestaurants();
  res.json({ data: restaurants });
});

exports.getPopularRestaurants = asyncHandler(async (req, res) => {
  const limit = Number(req.query.limit) || 5;
  const restaurants = await restaurantService.getPopularRestaurants(limit);
  res.json({ data: restaurants });
});

exports.getRestaurant = asyncHandler(async (req, res) => {
  const restaurant = await restaurantService.getRestaurantById(req.params.id);

  if (!restaurant) {
    res.status(404).json({ error: { message: 'Restaurant not found' } });
    return;
  }

  res.json({ data: restaurant });
});

exports.createRestaurant = asyncHandler(async (req, res) => {
  const payload = {
    ...req.body,
    recommendedMenu: normaliseMenu(req.body?.recommendedMenu)
  };

  const restaurant = await restaurantService.createRestaurant(payload);
  res.status(201).json({ data: restaurant });
});

exports.updateRestaurant = asyncHandler(async (req, res) => {
  const payload = {
    ...req.body,
    recommendedMenu: normaliseMenu(req.body?.recommendedMenu)
  };

  const updated = await restaurantService.updateRestaurant(req.params.id, payload);
  if (!updated) {
    res.status(404).json({ error: { message: 'Restaurant not found' } });
    return;
  }
  res.json({ data: updated });
});

exports.deleteRestaurant = asyncHandler(async (req, res) => {
  const deleted = await restaurantService.deleteRestaurant(req.params.id);
  if (!deleted) {
    res.status(404).json({ error: { message: 'Restaurant not found' } });
    return;
  }
  res.status(204).send();
});

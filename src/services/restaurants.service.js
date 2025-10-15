const path = require('path');
const { readFileSync } = require('fs');
const Restaurant = require('../models/restaurant.model');

const DATA_PATH = path.join(__dirname, '..', 'data', 'restaurants.json');

function readSeedDataSync() {
  const raw = readFileSync(DATA_PATH, 'utf8');
  return JSON.parse(raw);
}

async function getNextRestaurantId() {
  const max = await Restaurant.findOne().sort('-id').select('id').lean();
  return (max?.id || 0) + 1;
}

function getAllRestaurantsSync() {
  // 동기 데모 전용: 파일에서 즉시 반환
  const data = readSeedDataSync();
  return JSON.parse(JSON.stringify(data));
}

async function getAllRestaurants() {
  const docs = await Restaurant.find({}).lean();
  return docs;
}

async function getRestaurantById(id) {
  const numericId = Number(id);
  const doc = await Restaurant.findOne({ id: numericId }).lean();
  return doc || null;
}

async function getPopularRestaurants(limit = 5) {
  const docs = await Restaurant.find({}).sort({ rating: -1 }).limit(limit).lean();
  return docs;
}

async function createRestaurant(payload) {
  const requiredFields = ['name', 'category', 'location'];
  const missingField = requiredFields.find((field) => !payload[field]);
  if (missingField) {
    const error = new Error(`'${missingField}' is required`);
    error.statusCode = 400;
    throw error;
  }

  const nextId = await getNextRestaurantId();
  const doc = await Restaurant.create({
    id: nextId,
    name: payload.name,
    category: payload.category,
    location: payload.location,
    priceRange: payload.priceRange ?? '정보 없음',
    rating: payload.rating ?? 0,
    description: payload.description ?? '',
    recommendedMenu: Array.isArray(payload.recommendedMenu) ? payload.recommendedMenu : [],
    likes: 0,
    image: payload.image ?? ''
  });
  return doc.toObject();
}

async function resetStore() {
  const seed = readSeedDataSync();
  await Restaurant.deleteMany({});
  await Restaurant.insertMany(seed);
}

async function ensureSeededOnce() {
  const count = await Restaurant.estimatedDocumentCount();
  if (count > 0) return { seeded: false, count };
  const seed = readSeedDataSync();
  await Restaurant.insertMany(seed);
  return { seeded: true, count: seed.length };
}

async function updateRestaurant(id, payload) {
  const numericId = Number(id);
  const updated = await Restaurant.findOneAndUpdate(
    { id: numericId },
    {
      $set: {
        name: payload.name,
        category: payload.category,
        location: payload.location,
        priceRange: payload.priceRange,
        rating: payload.rating,
        description: payload.description,
        recommendedMenu: Array.isArray(payload.recommendedMenu) ? payload.recommendedMenu : undefined,
        image: payload.image,
      }
    },
    { new: true, runValidators: true, lean: true }
  );
  return updated;
}

async function deleteRestaurant(id) {
  const numericId = Number(id);
  const deleted = await Restaurant.findOneAndDelete({ id: numericId }).lean();
  return deleted;
}

module.exports = {
  getAllRestaurants,
  getAllRestaurantsSync,
  getRestaurantById,
  getPopularRestaurants,
  createRestaurant,
  updateRestaurant,
  deleteRestaurant,
  resetStore,
  ensureSeededOnce,
};
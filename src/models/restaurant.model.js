// src/models/restaurant.model.js
const mongoose = require('mongoose');

const RestaurantSchema = new mongoose.Schema(
  {
    id: { type: Number, required: true, unique: true, index: true },
    name: { type: String, required: true, index: true },
    category: { type: String, required: true, index: true },
    location: { type: String, required: true },
    priceRange: { type: String, default: '정보 없음' },
    rating: { type: Number, default: 0 },
    description: { type: String, default: '' },
    recommendedMenu: { type: [String], default: [] },
    likes: { type: Number, default: 0 },
    image: { type: String, default: '' }
  },
  {
    timestamps: true,
    versionKey: false,
    toObject: {
      transform: (_doc, ret) => {
        delete ret._id;
        return ret;
      }
    },
    toJSON: {
      transform: (_doc, ret) => {
        delete ret._id;
        return ret;
      }
    }
  }
);

module.exports = mongoose.models.Restaurant || mongoose.model('Restaurant', RestaurantSchema);
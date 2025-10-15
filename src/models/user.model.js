// src/models/user.model.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema(
  {
    // 로컬 계정 필드
    email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: function () {
        return this.provider === 'local';
      },
    },
    
    // OAuth 필드
    provider: {
      type: String,
      enum: ['local', 'google', 'naver'],
      default: 'local',
    },
    providerId: {
      type: String,
      sparse: true,
    },
    
    // 프로필 정보
    name: {
      type: String,
      required: true,
    },
    avatar: {
      type: String,
    },
    
    // 계정 상태
    isActive: {
      type: Boolean,
      default: true,
    },
    
    // 사용자 유형
    userType: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user',
    },
  },
  {
    timestamps: true,
  }
);

// 이메일과 providerId의 복합 유니크 인덱스 (같은 이메일도 provider가 다르면 허용)
userSchema.index({ email: 1, provider: 1 }, { unique: true });
// 동일 provider 내에서 providerId는 유일
userSchema.index({ provider: 1, providerId: 1 }, { unique: true, sparse: true });

// 비밀번호 해싱 미들웨어
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  
  if (this.password) {
    this.password = await bcrypt.hash(this.password, 12);
  }
  next();
});

// 비밀번호 검증 메서드
userSchema.methods.comparePassword = async function (candidatePassword) {
  if (!this.password) return false;
  return await bcrypt.compare(candidatePassword, this.password);
};

// 비밀번호 필드 제외 메서드
userSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};

const User = mongoose.model('User', userSchema);

module.exports = User;

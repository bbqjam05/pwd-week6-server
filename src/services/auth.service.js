// src/services/auth.service.js
const User = require('../models/user.model');

class AuthService {
  /**
   * 로컬 계정으로 회원가입
   */
  async register(userData) {
    const { email, password, name } = userData;

    // 이메일 중복 체크
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    
    if (existingUser) {
      throw new Error('이미 사용 중인 이메일입니다.');
    }

    // 사용자 생성
    const user = await User.create({
      email: email.toLowerCase(),
      password,
      name,
      provider: 'local',
    });

    return user;
  }

  /**
   * 현재 로그인한 사용자 정보 조회
   */
  async getCurrentUser(userId) {
    const user = await User.findById(userId);
    
    if (!user) {
      throw new Error('사용자를 찾을 수 없습니다.');
    }

    return user;
  }

  /**
   * 사용자 ID로 조회
   */
  async getUserById(userId) {
    const user = await User.findById(userId);
    
    if (!user) {
      throw new Error('사용자를 찾을 수 없습니다.');
    }

    return user;
  }
}

module.exports = new AuthService();

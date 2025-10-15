// src/services/users.service.js
const User = require('../models/user.model');

class UsersService {
  /**
   * 사용자 프로필 조회
   */
  async getProfile(userId) {
    const user = await User.findById(userId);
    
    if (!user) {
      throw new Error('사용자를 찾을 수 없습니다.');
    }

    return user;
  }

  /**
   * 사용자 프로필 업데이트
   */
  async updateProfile(userId, updateData) {
    const { name, avatar } = updateData;

    const user = await User.findById(userId);
    
    if (!user) {
      throw new Error('사용자를 찾을 수 없습니다.');
    }

    // 업데이트 가능한 필드만 수정
    if (name) user.name = name;
    if (avatar !== undefined) user.avatar = avatar;

    await user.save();

    return user;
  }

  /**
   * 비밀번호 변경 (로컬 계정만)
   */
  async changePassword(userId, currentPassword, newPassword) {
    const user = await User.findById(userId);
    
    if (!user) {
      throw new Error('사용자를 찾을 수 없습니다.');
    }

    // 로컬 계정 확인
    if (user.provider !== 'local') {
      throw new Error('소셜 로그인 계정은 비밀번호를 변경할 수 없습니다.');
    }

    // 현재 비밀번호 확인
    const isMatch = await user.comparePassword(currentPassword);
    
    if (!isMatch) {
      throw new Error('현재 비밀번호가 올바르지 않습니다.');
    }

    // 새 비밀번호 설정
    user.password = newPassword;
    await user.save();

    return user;
  }

  /**
   * 계정 삭제 (비활성화)
   */
  async deleteAccount(userId) {
    const user = await User.findById(userId);
    
    if (!user) {
      throw new Error('사용자를 찾을 수 없습니다.');
    }

    user.isActive = false;
    await user.save();

    return user;
  }

  /**
   * 모든 사용자 목록 조회 (관리자 전용)
   */
  async getAllUsers() {
    const users = await User.find({ isActive: true })
      .select('-password')
      .sort({ createdAt: -1 });
    
    return users;
  }

  /**
   * 사용자 유형 변경 (관리자 전용)
   */
  async changeUserType(userId, newUserType) {
    const user = await User.findById(userId);
    
    if (!user) {
      throw new Error('사용자를 찾을 수 없습니다.');
    }

    if (!['user', 'admin'].includes(newUserType)) {
      throw new Error('유효하지 않은 사용자 유형입니다.');
    }

    user.userType = newUserType;
    await user.save();

    return user;
  }
}

module.exports = new UsersService();

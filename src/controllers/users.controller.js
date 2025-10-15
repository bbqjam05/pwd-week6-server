// src/controllers/users.controller.js
const usersService = require('../services/users.service');
const asyncHandler = require('../utils/asyncHandler');

class UsersController {
  /**
   * 내 프로필 조회
   * GET /api/users/profile
   */
  getProfile = asyncHandler(async (req, res) => {
    const user = await usersService.getProfile(req.user._id);

    res.json({
      success: true,
      data: { user },
    });
  });

  /**
   * 내 프로필 수정
   * PUT /api/users/profile
   */
  updateProfile = asyncHandler(async (req, res) => {
    const { name, avatar } = req.body;

    const user = await usersService.updateProfile(req.user._id, {
      name,
      avatar,
    });

    res.json({
      success: true,
      message: '프로필이 수정되었습니다.',
      data: { user },
    });
  });

  /**
   * 비밀번호 변경
   * PUT /api/users/password
   */
  changePassword = asyncHandler(async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    // 유효성 검사
    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: '현재 비밀번호와 새 비밀번호는 필수입니다.',
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: '새 비밀번호는 최소 6자 이상이어야 합니다.',
      });
    }

    await usersService.changePassword(req.user._id, currentPassword, newPassword);

    res.json({
      success: true,
      message: '비밀번호가 변경되었습니다.',
    });
  });

  /**
   * 계정 삭제
   * DELETE /api/users/account
   */
  deleteAccount = asyncHandler(async (req, res) => {
    await usersService.deleteAccount(req.user._id);

    // 로그아웃 처리
    req.logout((err) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: '로그아웃 중 오류가 발생했습니다.',
        });
      }

      req.session.destroy((err) => {
        if (err) {
          return res.status(500).json({
            success: false,
            message: '세션 삭제 중 오류가 발생했습니다.',
          });
        }

        res.clearCookie('connect.sid');
        res.json({
          success: true,
          message: '계정이 삭제되었습니다.',
        });
      });
    });
  });

  /**
   * 모든 사용자 목록 조회 (관리자 전용)
   * GET /api/users/all
   */
  getAllUsers = asyncHandler(async (req, res) => {
    const users = await usersService.getAllUsers();

    res.json({
      success: true,
      data: { users },
    });
  });

  /**
   * 사용자 유형 변경 (관리자 전용)
   * PUT /api/users/:userId/type
   */
  changeUserType = asyncHandler(async (req, res) => {
    const { userId } = req.params;
    const { userType } = req.body;

    if (!userType || !['user', 'admin'].includes(userType)) {
      return res.status(400).json({
        success: false,
        message: '유효한 사용자 유형을 입력해주세요. (user 또는 admin)',
      });
    }

    const user = await usersService.changeUserType(userId, userType);

    res.json({
      success: true,
      message: '사용자 유형이 변경되었습니다.',
      data: { user },
    });
  });
}

module.exports = new UsersController();

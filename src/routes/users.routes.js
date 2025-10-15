// src/routes/users.routes.js
const express = require('express');
const usersController = require('../controllers/users.controller');
const { isAuthenticated, isLocalAccount, isAdmin } = require('../middleware/auth.middleware');

const router = express.Router();

// 내 프로필 조회
router.get('/profile', isAuthenticated, usersController.getProfile);

// 내 프로필 수정
router.put('/profile', isAuthenticated, usersController.updateProfile);

// 비밀번호 변경 (로컬 계정만)
router.put('/password', isLocalAccount, usersController.changePassword);

// 계정 삭제
router.delete('/account', isAuthenticated, usersController.deleteAccount);

// 모든 사용자 목록 조회 (관리자 전용)
router.get('/all', isAdmin, usersController.getAllUsers);

// 사용자 유형 변경 (관리자 전용)
router.put('/:userId/type', isAdmin, usersController.changeUserType);

module.exports = router;

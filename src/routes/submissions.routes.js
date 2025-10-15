const express = require('express');
const controller = require('../controllers/submissions.controller');
const { isAuthenticated, isAdmin } = require('../middleware/auth.middleware');

const router = express.Router();

// 모든 사용자가 제출할 수 있음
router.post('/', isAuthenticated, controller.create);

// 관리자만 접근 가능
router.get('/', isAdmin, controller.list);
router.get('/:id', isAdmin, controller.get);
router.put('/:id', isAdmin, controller.update);
router.delete('/:id', isAdmin, controller.remove);

module.exports = router;


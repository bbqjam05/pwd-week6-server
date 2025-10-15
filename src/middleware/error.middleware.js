module.exports = function errorHandler(err, req, res, next) {
  const status = err.statusCode || 500;
  const payload = {
    success: false,
    message: err.message || '서버 내부 오류가 발생했습니다.',
    data: null
  };

  // 개발 환경에서만 스택 트레이스 포함
  if (process.env.NODE_ENV !== 'production' && err.stack) {
    payload.stack = err.stack;
  }

  console.error('Error:', err.message, err.stack);
  res.status(status).json(payload);
};
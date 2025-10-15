// change-user-type.js
// 사용자 유형 변경 스크립트

const mongoose = require('mongoose');
const User = require('./src/models/user.model');
require('dotenv').config();

const changeUserType = async (email, newUserType) => {
  try {
    // 데이터베이스 연결
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/ajou-foodmap');
    console.log('데이터베이스에 연결되었습니다.');

    // 사용자 찾기
    const user = await User.findOne({ email: email.toLowerCase() });
    
    if (!user) {
      console.log('사용자를 찾을 수 없습니다:', email);
      return;
    }

    // 유효한 유형인지 확인
    if (!['user', 'admin'].includes(newUserType)) {
      console.log('유효하지 않은 사용자 유형입니다. (user 또는 admin)');
      return;
    }

    // 사용자 유형 변경
    user.userType = newUserType;
    await user.save();
    
    console.log('사용자 유형이 변경되었습니다:');
    console.log('이메일:', user.email);
    console.log('이름:', user.name);
    console.log('이전 유형:', user.userType === 'admin' ? '관리자' : '일반 사용자');
    console.log('새 유형:', newUserType === 'admin' ? '관리자' : '일반 사용자');

  } catch (error) {
    console.error('사용자 유형 변경 중 오류 발생:', error);
  } finally {
    await mongoose.disconnect();
    console.log('데이터베이스 연결이 종료되었습니다.');
  }
};

// 명령행 인수로 이메일과 유형을 받음
const email = process.argv[2];
const userType = process.argv[3];

if (!email || !userType) {
  console.log('사용법: node change-user-type.js <이메일> <user|admin>');
  console.log('예시: node change-user-type.js user@example.com admin');
  process.exit(1);
}

changeUserType(email, userType);
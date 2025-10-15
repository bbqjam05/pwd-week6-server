// create-admin.js
// 관리자 계정 생성 스크립트

const mongoose = require('mongoose');
const User = require('./src/models/user.model');
require('dotenv').config();

const createAdminUser = async () => {
  try {
    // 데이터베이스 연결
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/ajou-foodmap');
    console.log('데이터베이스에 연결되었습니다.');

    // 기존 관리자 계정 확인
    const existingAdmin = await User.findOne({ userType: 'admin' });
    if (existingAdmin) {
      console.log('이미 관리자 계정이 존재합니다:', existingAdmin.email);
      return;
    }

    // 관리자 계정 생성
    const adminUser = new User({
      email: 'admin@ajou.ac.kr',
      password: 'admin123!',
      name: '관리자',
      userType: 'admin',
      provider: 'local'
    });

    await adminUser.save();
    console.log('관리자 계정이 생성되었습니다:');
    console.log('이메일: admin@ajou.ac.kr');
    console.log('비밀번호: admin123!');
    console.log('사용자 유형: admin');

  } catch (error) {
    console.error('관리자 계정 생성 중 오류 발생:', error);
  } finally {
    await mongoose.disconnect();
    console.log('데이터베이스 연결이 종료되었습니다.');
  }
};

createAdminUser();
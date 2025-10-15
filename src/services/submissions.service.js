const Submission = require('../models/submission.model');

async function getNextSubmissionId() {
  const max = await Submission.findOne().sort('-id').select('id').lean();
  return (max?.id || 0) + 1;
}

async function listSubmissions(status) {
  const filter = status ? { status } : {};
  return await Submission.find(filter).sort({ createdAt: -1 }).lean();
}

async function getSubmissionById(id) {
  const numericId = Number(id);
  return await Submission.findOne({ id: numericId }).lean();
}

async function createSubmission(payload) {
  const nextId = await getNextSubmissionId();
  const doc = await Submission.create({ id: nextId, ...payload });
  return doc.toObject();
}

async function updateSubmission(id, payload) {
  const numericId = Number(id);
  return await Submission.findOneAndUpdate(
    { id: numericId },
    { $set: payload },
    { new: true, runValidators: true, lean: true }
  );
}

async function deleteSubmission(id) {
  const numericId = Number(id);
  return await Submission.findOneAndDelete({ id: numericId }).lean();
}

module.exports = {
  listSubmissions,
  getSubmissionById,
  createSubmission,
  updateSubmission,
  deleteSubmission,
};


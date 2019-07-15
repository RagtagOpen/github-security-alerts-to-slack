module.exports = {
  post: jest.fn(() => Promise.resolve({ status: 200, statusText: "OK" }))
};

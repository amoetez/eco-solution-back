const mongoose = require("mongoose");

const connectMongo = async () => {
  try {
    mongoose.set("strictQuery", true);
    mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
    });
    console.log("DB is Connected");
  } catch (err) {
    console.error(err.message);
  }
};

module.exports = connectMongo;

require("dotenv").config();
const path = require("path");
const express = require("express");
const cookieParser = require("cookie-parser");
const app = express();
const port = 5050;
const body_parser = require("body-parser");
const connectMongo = require("./utils/connect");
const projet_router = require("./routes/projetRoute");
const article_router = require("./routes/articleRoute");
const service_router = require("./routes/serviceRoute");
const contactInfo_router = require("./routes/contactInfoRoute");
const coordonneClient_router = require("./routes/coordonneClientRoute");
const admin = require("./routes/adminRoute");
const puissance_router = require("./routes/puissanceRoute");
const devis_router = require("./routes/devisRoute");
const indicateur_router = require("./routes/indicateurRoute");
const cors = require("cors");
connectMongo();
const corsOptions = {
  origin: "*",
  credentials: true,
};
// ["http://localhost:3000", "http://localhost:3001"];
app.use(cors(corsOptions));
app.use(cookieParser());
app.use(express.static(path.join(process.cwd(), 'uploads')));
app.use(body_parser.json());
app.use(projet_router);
app.use(article_router);
app.use(service_router);
app.use(devis_router);
app.use(contactInfo_router);
app.use(coordonneClient_router);
app.use(admin);
app.use(puissance_router);
app.use(indicateur_router);
app.listen(port, () => {
  console.log(`Running at Port ${port}`);
});

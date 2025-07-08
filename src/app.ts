import express, { Request, Response, Application, NextFunction } from 'express';
import helmet from 'helmet';
import cors from "cors";
import dotenv from "dotenv";
import morgan from "morgan";
import compression from "compression"
import rateLimit from 'express-rate-limit';
import rootRouter from './routes';
import errorHandlerMiddleware from './middlewares/errorHandler';

dotenv.config()

const app: Application = express();
const port = process.env.PORT || 3000;

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 1 dakika
  max: 100, // 1 dk içinde max istek
  standardHeaders: true, 
  legacyHeaders: false,
  message: "Cok fazla istek gonderdiniz, lutfen biraz bekleyin."
})

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://yourdomain.com'] 
    : ['http://localhost:5000', 'http://localhost:3000'],
  credentials: true
}));
app.use(limiter);
app.use(morgan("dev"));
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use("/api", rootRouter)


// Routes
app.get('/', (req: Request, res: Response) => {
  res.json({ message: 'TypeScript Express sunucusu çalışıyor!' });
});

app.use(errorHandlerMiddleware);

process.on("uncaughtException", (error) => {
  console.error("Uncaught Exception:", error);
  process.exit(1); // Critical errors için uygulamayı kapat
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason);
  process.exit(1);
});

// Hemen kapatma uygulamayı
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  process.exit(0);
});

app.listen(port, () => {
  console.log(`Sunucu http://localhost:${port} adresinde çalışıyor`);
});
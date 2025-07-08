import { Response as ExpressResponse } from 'express';

interface ApiResponse {
  success: boolean;
  data?: any;
  message?: string;
  error?: {
    code?: string;
    details?: any;
  };
  timestamp: Date;
}

class AppResponse {
  private data: any;
  private message: string | null;

  constructor(data: any = null, message: string | null = null) {
    this.data = data;
    this.message = message;
  }

  success(res: ExpressResponse): void {
    const response: ApiResponse = {
      success: true,
      data: this.data,
      message: this.message ?? "İşlem Başarılı",
      timestamp: new Date()
    };
    res.status(200).json(response);
  }

  created(res: ExpressResponse): void {
    const response: ApiResponse = {
      success: true,
      data: this.data,
      message: this.message ?? "Başarıyla oluşturuldu",
      timestamp: new Date()
    };
    res.status(201).json(response);
  }

  // Hata yanıtları için statik yöntemler
  static error(res: ExpressResponse, statusCode: number, message: string, errorCode?: string, details?: any): void {
    const response: ApiResponse = {
      success: false,
      message,
      error: {
        code: errorCode,
        details
      },
      timestamp: new Date()
    };
    res.status(statusCode).json(response);
  }
}

export default AppResponse;
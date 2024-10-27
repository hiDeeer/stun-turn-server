import { Injectable, OnModuleInit } from '@nestjs/common';
import * as dgram from 'dgram';
import * as net from 'net'; // TCP 모듈 추가
import * as fs from 'fs';
import * as https from 'https';
import * as dotenv from 'dotenv';

dotenv.config(); // .env 파일 로드

@Injectable()
export class TurnService implements OnModuleInit {
  private udpServer: dgram.Socket; // UDP 서버
  private tcpServer: net.Server; // TCP 서버
  private clients: {
    address: string;
    port: number;
    username: string;
    password: string;
  }[] = [];

  private validUsers = {
    "imnotMango": 'test1234',
  };

  private static readonly STUN_MAGIC_COOKIE = 0x2112A442;
  private static readonly BINDING_REQUEST = 0x0001;
  private static readonly BINDING_RESPONSE = 0x0101;
  private static readonly AUTH_REQUEST = 0x0002;

  private static readonly BUFFER_SIZE = 20; // 기본 STUN 응답 버퍼 크기

  onModuleInit() {
    const sslOptions = {
      key: fs.readFileSync(process.env.SSL_KEY),
      cert: fs.readFileSync(process.env.SSL_CERT),
    };

    const httpsServer = https.createServer(sslOptions);
    httpsServer.listen(443, () => {
    });

    // UDP 서버 설정
    this.udpServer = dgram.createSocket('udp4');
    this.udpServer.on('message', (msg, rinfo) => {
      const parsedMessage = this.parseMessage(msg);
      console.log('Received message:', parsedMessage);

      // STUN 요청 및 인증 요청 처리
      if (parsedMessage && parsedMessage.type === 'stun') {
        this.handleStunRequest(msg, rinfo); // STUN 요청 처리
      } else if (parsedMessage && parsedMessage.type === 'auth') {
        this.handleAuthRequest(parsedMessage.username, parsedMessage.password, rinfo);
      } else {
        this.logError('Unknown message type or missing parameters:', rinfo.address);
      }
    });

    this.udpServer.bind(3478, '0.0.0.0', () => {
      console.log('TURN/STUN server is running on UDP port 3478');
    });
    // TCP 서버 설정
    this.tcpServer = net.createServer((socket) => {
      socket.on('data', (data) => {
        const parsedMessage = this.parseMessage(data);
        console.log('Received TCP message:', parsedMessage);

        // TCP에서 STUN 요청 및 인증 요청 처리
        if (parsedMessage && parsedMessage.type === 'stun') {
          this.handleStunRequest(data, {
            address: socket.remoteAddress,
            port: socket.remotePort,
            family: socket.remoteFamily as 'IPv4' | 'IPv6',
            size: data.length
          }); // TCP에서 STUN 요청 처리
        } else if (parsedMessage && parsedMessage.type === 'auth') {
          this.handleAuthRequest(parsedMessage.username, parsedMessage.password, {
            address: socket.remoteAddress,
            port: socket.remotePort,
            family: socket.remoteFamily as 'IPv4' | 'IPv6',
            size: data.length,
          });
        } else {
          this.logError('Unknown message type or missing parameters:', socket.remoteAddress);
        }
      });

      socket.on('error', (err) => {
        this.logError('TCP Socket Error:', err);
      });
    });

    this.tcpServer.listen(3479, '0.0.0.0', () => {
      console.log('TURN server is running on TCP port 3479');
    });
  }

  handleAuthRequest(username: string, password: string, rinfo: dgram.RemoteInfo) {
    if (this.isValidUser(username, password)) {
      if (!this.clients.some(client => client.address === rinfo.address && client.port === rinfo.port)) {
        this.clients.push({
          address: rinfo.address,
          port: rinfo.port,
          username,
          password,
        });
        console.log(`Client authenticated: ${username} from ${rinfo.address}:${rinfo.port}`);
        this.relayMessage(Buffer.from('Authentication success'), rinfo);
      } else {
        this.logError('Client already authenticated:', username);
        this.relayMessage(Buffer.from('Already authenticated'), rinfo);
      }
    } else {
      this.logError('Authentication failed for user:', username);
      this.relayMessage(Buffer.from('Authentication failed'), rinfo);
    }
  }

  isValidUser(username: string, password: string): boolean {
    return this.validUsers[username] === password;
  }

  parseMessage(msg: Buffer) {
    try {
      const messageType = msg.readUInt16BE(0);
      const magicCookie = msg.readUInt32BE(4);

      if (magicCookie !== TurnService.STUN_MAGIC_COOKIE) {
        console.log('Invalid magic cookie:', magicCookie);
        return null;
      }

      console.log('Message Type:', messageType);

      if (messageType === TurnService.BINDING_REQUEST) {
        return { type: 'stun' }; // STUN 요청 타입
      } else if (messageType === TurnService.AUTH_REQUEST) {
        const username = msg.toString('utf8', 20, 36); // username 위치
        const password = msg.toString('utf8', 36, 52); // password 위치
        return { type: 'auth', username, password }; // 인증 요청 타입
      } else if (messageType === 3) {
        // 메시지 타입 3 처리 추가
        console.warn('Received unknown message type 3. Ignoring it.'); // 타입 3에 대한 경고 로그
        return null; // 무시
      }

      console.log('Unknown message type:', messageType);
      return null; // 알 수 없는 메시지 타입
    } catch (error) {
      console.error('Error parsing message:', error);
      return null;
    }
  }

  handleStunRequest(msg: Buffer, rinfo: dgram.RemoteInfo | { address: string; port: number }) {
    const response = Buffer.alloc(TurnService.BUFFER_SIZE);
    response.writeUInt16BE(TurnService.BINDING_RESPONSE, 0);
    response.writeUInt16BE(0, 2); // 메시지 길이
    response.writeUInt32BE(TurnService.STUN_MAGIC_COOKIE, 4); // Magic Cookie

    const transactionId = Math.floor(Math.random() * 0xFFFFFFFF);
    response.writeUInt32BE(transactionId, 8); // 트랜잭션 ID의 일부

    // XOR Mapped Address 추가
    const xorMappedAddress = this.createXorMappedAddress(rinfo);
    xorMappedAddress.copy(response, 12); // XOR Mapped Address를 response의 12번째 바이트부터 복사

    if ('port' in rinfo) {
      this.udpServer.send(response, 0, response.length, rinfo.port, rinfo.address, (err) => {
        if (err) {
          this.logError('Error sending STUN response:', err);
        } else {
          console.log(`STUN response sent to ${rinfo.address}:${rinfo.port}`);
        }
      });
    } else {
      this.relayMessage(response, rinfo); // TCP에서의 응답 처리
    }
  }

  private createXorMappedAddress(rinfo: dgram.RemoteInfo | { address: string; port: number }): Buffer {
    const xorMappedAddress = Buffer.alloc(12);
    xorMappedAddress.writeUInt16BE(0x0020, 0); // Attribute Type (XOR Mapped Address)
    xorMappedAddress.writeUInt16BE(8, 2); // Attribute Length
    xorMappedAddress.writeUInt8(0x01, 4); // 주소 패밀리 (IPv4)
    xorMappedAddress.writeUInt16BE((rinfo.port as number) ^ 0x2112, 6); // XOR 포트

    // IP를 XOR하여 추가
    const ip = (rinfo.address as string).split('.').map((octet: string) => parseInt(octet, 10));
    for (let i = 0; i < 4; i++) {
      const xorValue = ip[i] ^ (TurnService.STUN_MAGIC_COOKIE >> ((3 - i) * 8)); // XOR IP
      xorMappedAddress.writeUInt8(xorValue & 0xFF, 8 + i); // 0~255 범위로 제한하여 쓰기
    }

    return xorMappedAddress;
  }

  relayMessage(msg: Buffer, rinfo: dgram.RemoteInfo) {
    this.clients.forEach((client) => {
      if (client.address !== rinfo.address || client.port !== rinfo.port) {
        this.udpServer.send(msg, 0, msg.length, client.port, client.address, (err) => {
          if (err) {
            this.logError('Error relaying message:', err);
          }
        });
      }
    });
  }

  logError(message: string, error?: any) {
    console.error(message, error);
  }
}

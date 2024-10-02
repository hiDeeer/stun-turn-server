// src/turn/turn.service.ts
import { Injectable, OnModuleInit } from '@nestjs/common';
import * as dgram from 'dgram';
import * as fs from 'fs';
import * as https from 'https';
import * as dotenv from 'dotenv';

dotenv.config(); // .env 파일 로드

@Injectable()
export class TurnService implements OnModuleInit {
  private server: dgram.Socket;
  private clients: {
    address: string;
    port: number;
    username: string;
    password: string;
  }[] = [];

  private validUsers = {
    "imnotMango": 'test1234',
  };

  onModuleInit() {
    const sslOptions = {
      key: fs.readFileSync(process.env.SSL_KEY),
      cert: fs.readFileSync(process.env.SSL_CERT),
    };

    const httpsServer = https.createServer(sslOptions);
    httpsServer.listen(443, () => {
      console.log('HTTPS server running on port 443');
    });

    this.server = dgram.createSocket('udp4');

    this.server.on('message', (msg, rinfo) => {
      const parsedMessage = this.parseMessage(msg);
      console.log(parsedMessage);

      if (parsedMessage && parsedMessage.type === 'stun') {
        this.handleStunRequest(msg, rinfo); // STUN 요청 처리
      } else if (parsedMessage && parsedMessage.type === 'auth' && this.isValidUser(parsedMessage.username, parsedMessage.password)) {
        this.clients.push({
          address: rinfo.address,
          port: rinfo.port,
          username: parsedMessage.username,
          password: parsedMessage.password,
        });
        this.relayMessage(msg, rinfo);
      } else {
        console.error('Authentication failed or unknown message type:', rinfo.address);
      }
    });

    this.server.bind(3478, '0.0.0.0', () => {
      console.log('TURN/STUN server is running on port 3478');
    });
  }

  isValidUser(username: string, password: string): boolean {
    return this.validUsers[username] === password;
  }

  parseMessage(msg: Buffer) {
    try {
      const messageType = msg.readUInt16BE(0);
      const magicCookie = msg.readUInt32BE(4);
      const STUN_MAGIC_COOKIE = 0x2112A442;

      if (magicCookie !== STUN_MAGIC_COOKIE) {
        return null;
      }

      if (messageType === 0x0001) {
        return { type: 'stun' };
      } else if (messageType === 0x0002) {
        return { type: 'auth', username: 'imnotMango', password: 'test1234' };
      }

      return null;
    } catch (error) {
      console.error('Error parsing message:', error);
      return null;
    }
  }

  handleStunRequest(msg: Buffer, rinfo: dgram.RemoteInfo) {
    const response = Buffer.alloc(20);
    response.writeUInt16BE(0x0101, 0); // 메시지 타입: Binding Success Response
    response.writeUInt16BE(0, 2); // 메시지 길이
    response.writeUInt32BE(0x2112A442, 4); // Magic Cookie
    response.writeUInt32BE(Math.random() * 0xFFFFFFFF, 8); // 트랜잭션 ID의 일부

    // XOR Mapped Address 추가
    const xorMappedAddress = Buffer.alloc(8);
    xorMappedAddress.writeUInt16BE(0x0020, 0); // Attribute Type (XOR Mapped Address)
    xorMappedAddress.writeUInt16BE(8, 2); // Attribute Length
    xorMappedAddress.writeUInt8(0x01, 4); // 주소 패밀리 (IPv4)
    xorMappedAddress.writeUInt16BE(rinfo.port ^ 0x2112, 6); // XOR 포트
    const ip = rinfo.address.split('.').map((octet: string) => parseInt(octet, 10));
    for (let i = 0; i < 4; i++) {
      xorMappedAddress.writeUInt8(ip[i] ^ (0x2112A442 >> ((3 - i) * 8)), 8 + i); // XOR IP
    }

    // 응답에 XOR Mapped Address 추가
    response.writeUInt16BE(xorMappedAddress.readUInt16BE(0), 12);
    response.writeUInt16BE(xorMappedAddress.readUInt16BE(2), 14);
    response.writeUInt8(xorMappedAddress.readUInt8(4), 16);
    response.writeUInt16BE(xorMappedAddress.readUInt16BE(6), 18);

    this.server.send(response, 0, response.length, rinfo.port, rinfo.address, (err) => {
      if (err) {
        console.error('Error sending STUN response:', err);
      } else {
        console.log(`STUN response sent to ${rinfo.address}:${rinfo.port}`);
      }
    });
  }

  relayMessage(msg: Buffer, rinfo: dgram.RemoteInfo) {
    this.clients.forEach((client) => {
      if (client.address !== rinfo.address || client.port !== rinfo.port) {
        this.server.send(msg, 0, msg.length, client.port, client.address, (err) => {
          if (err) {
            throw new Error('Error relaying message');
          }
        });
      }
    });
  }
}

FROM node:22-alpine

WORKDIR /app

# 只拷 package.json，避免通配符和重定向错误
COPY package.json ./

RUN npm install

# 再拷全部项目
COPY . .

ENV HOST=0.0.0.0
EXPOSE 3000

CMD ["npm", "run", "dev", "--", "-H", "0.0.0.0"]

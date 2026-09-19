const router = require('express').Router();
const { authMiddleware } = require('../middleware/auth');
const crypto = require('crypto');
const messages = [], lastSent = new Map();
router.use(authMiddleware);
router.get('/', (req,res) => { res.set('Cache-Control','no-store'); res.json({messages,ephemeral:true}); });
router.post('/', (req,res) => {
 const text=typeof req.body.text==='string'?req.body.text.trim():'';
 if(!text||text.length>1000)return res.status(400).json({error:'消息长度应为 1–1000 字符'});
 const now=Date.now(),key=String(req.user.id);
 for(const [id,time] of lastSent)if(now-time>60000)lastSent.delete(id);
 if(now-(lastSent.get(key)||0)<1500)return res.status(429).json({error:'发送过快'});
 if(lastSent.size>=10000&&!lastSent.has(key))return res.status(503).json({error:'聊天室繁忙'});
 lastSent.set(key,now);
 const message={id:crypto.randomUUID(),username:req.user.username,userId:req.user.id,text,time:now};
 messages.push(message);if(messages.length>100)messages.shift();res.status(201).json(message);
});
module.exports=router;

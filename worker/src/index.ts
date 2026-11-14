export interface Env{DB:D1Database;FIREBASE_PROJECT_ID:string;ADMIN_EMAIL:string;PAYSTACK_SECRET_KEY:string}
const json=(data:unknown,status=200)=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json","access-control-allow-origin":"*","access-control-allow-headers":"authorization,content-type","access-control-allow-methods":"GET,POST,OPTIONS"}});
const b64=(s:string)=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0));
async function identity(req:Request,env:Env){const h=req.headers.get("authorization")||"";const token=h.startsWith("Bearer ")?h.slice(7):"";if(!token)throw new Error("Sign in required");const parts=token.split(".");if(parts.length!==3)throw new Error("Invalid login token");const header=JSON.parse(new TextDecoder().decode(b64(parts[0]))),claims=JSON.parse(new TextDecoder().decode(b64(parts[1])));if(claims.aud!==env.FIREBASE_PROJECT_ID||claims.iss!=="https://securetoken.google.com/"+env.FIREBASE_PROJECT_ID||claims.exp<Date.now()/1000||!claims.sub)throw new Error("Login token expired or invalid");const keys=await fetch("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com").then(r=>r.json()) as {keys:Array<JsonWebKey & {kid:string}>};const jwk=keys.keys.find(k=>k.kid===header.kid);if(!jwk)throw new Error("Unable to verify login token");const key=await crypto.subtle.importKey("jwk",jwk,{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["verify"]);const ok=await crypto.subtle.verify("RSASSA-PKCS1-v1_5",key,b64(parts[2]),new TextEncoder().encode(parts[0]+"."+parts[1]));if(!ok)throw new Error("Invalid login signature");return{uid:claims.sub as string,email:String(claims.email||"").toLowerCase(),emailVerified:claims.email_verified===true,name:String(claims.name||"")};}
const id=()=>crypto.randomUUID();const code=()=>crypto.randomUUID().replace(/-/g,"").slice(0,10).toUpperCase();
async function user(env:Env,uid:string){return env.DB.prepare("SELECT * FROM users WHERE firebase_uid=?").bind(uid).first<any>();}
async function resetInactiveBalance(env:Env,me:any){
 const last=me.last_hash_at?Date.parse(me.last_hash_at):0;
 if(me.session_active||!last||Date.now()-last<=72*3600000||me.mining_balance_sats<=0)return;
 const reservedRow=await env.DB.prepare("SELECT COALESCE(SUM(amount_sats),0) AS reserved FROM withdrawals WHERE user_id=? AND asset='BTC' AND status IN ('pending','approved')").bind(me.id).first<any>();
 const reserved=Number(reservedRow?.reserved||0),resetAmount=Math.max(0,me.mining_balance_sats-reserved),resetRef="RESET-"+me.id+"-"+last;
 if(resetAmount<=0)return;
 await env.DB.batch([
  env.DB.prepare("UPDATE users SET mining_balance_sats=mining_balance_sats-?,last_inactivity_reset_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=? AND last_hash_at=? AND mining_balance_sats=? AND last_hash_at<=datetime('now','-72 hours')").bind(resetAmount,me.id,me.last_hash_at,me.mining_balance_sats),
  env.DB.prepare("INSERT OR IGNORE INTO ledger(id,user_id,entry_type,amount_sats,status,reference,note) SELECT ?,?, 'inactivity_reset',?,'completed',?,'Unreserved virtual HASH balance reset after 72 hours inactivity' WHERE EXISTS(SELECT 1 FROM users WHERE id=? AND mining_balance_sats=? AND last_inactivity_reset_at>=datetime('now','-2 seconds'))").bind(id(),me.id,-resetAmount,resetRef,me.id,reserved)
 ]);
}
async function activate(env:Env,reference:string,transactionId:string){
 const p=await env.DB.prepare("SELECT * FROM payments WHERE reference=?").bind(reference).first<any>();
 if(!p)throw new Error("Payment reference not found");
 if(p.amount_minor!==10000||p.currency!=="KES")throw new Error("Payment amount or currency mismatch");
 await env.DB.batch([
  env.DB.prepare("UPDATE payments SET status='success',paystack_transaction_id=?,paid_at=COALESCE(paid_at,CURRENT_TIMESTAMP),verified_at=CURRENT_TIMESTAMP WHERE reference=? AND status='pending' AND amount_minor=10000 AND currency='KES'").bind(transactionId,reference),
  env.DB.prepare("UPDATE users SET activated=1,activated_at=COALESCE(activated_at,CURRENT_TIMESTAMP),status='active',updated_at=CURRENT_TIMESTAMP WHERE id=? AND EXISTS(SELECT 1 FROM payments WHERE reference=? AND status='success')").bind(p.user_id,reference),
  env.DB.prepare("INSERT OR IGNORE INTO ledger(id,user_id,entry_type,amount_cents,status,reference,note) SELECT ?,referrer_user_id,'referral_reward',reward_cents,'pending_credit',?,'Verified referral activation' FROM referrals WHERE referred_user_id=? AND status='pending_activation' AND EXISTS(SELECT 1 FROM payments WHERE reference=? AND status='success')").bind(id(),reference,p.user_id,reference),
  env.DB.prepare("UPDATE users SET referral_balance_cents=referral_balance_cents+(SELECT amount_cents FROM ledger WHERE reference=? AND entry_type='referral_reward' AND status='pending_credit'),updated_at=CURRENT_TIMESTAMP WHERE id IN (SELECT user_id FROM ledger WHERE reference=? AND entry_type='referral_reward' AND status='pending_credit')").bind(reference,reference),
  env.DB.prepare("UPDATE ledger SET status='completed' WHERE reference=? AND entry_type='referral_reward' AND status='pending_credit'").bind(reference),
  env.DB.prepare("UPDATE referrals SET status='rewarded',rewarded_at=CURRENT_TIMESTAMP,activation_reference=? WHERE referred_user_id=? AND status='pending_activation' AND EXISTS(SELECT 1 FROM ledger WHERE reference=? AND entry_type='referral_reward' AND status='completed')").bind(reference,p.user_id,reference)
 ]);
}
async function handle(req:Request,env:Env):Promise<Response>{if(req.method==="OPTIONS")return json({ok:true});const url=new URL(req.url),path=url.pathname;
if(path==="/health")return json({ok:true,service:"mutah-hash-api"});
if(path==="/api/paystack/webhook"&&req.method==="POST"){
 const raw=await req.text(),sig=req.headers.get("x-paystack-signature")||"";
 const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(env.PAYSTACK_SECRET_KEY),{name:"HMAC",hash:"SHA-512"},false,["sign"]);
 const digest=new Uint8Array(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(raw)));
 const hex=Array.from(digest).map(x=>x.toString(16).padStart(2,"0")).join("");
 let diff=hex.length^sig.length;for(let i=0;i<Math.max(hex.length,sig.length);i++)diff|=(hex.charCodeAt(i)||0)^(sig.charCodeAt(i)||0);
 if(diff!==0)return json({error:"Invalid webhook signature"},401);
 let event:any;try{event=JSON.parse(raw)}catch{return json({error:"Invalid webhook payload"},400)}
 if(event.event==="charge.success"&&event.data?.reference){
  const reference=String(event.data.reference),payment=await env.DB.prepare("SELECT * FROM payments WHERE reference=?").bind(reference).first<any>();
  if(!payment)return json({error:"Unknown payment reference"},404);
  const verify=await fetch("https://api.paystack.co/transaction/verify/"+encodeURIComponent(reference),{headers:{Authorization:"Bearer "+env.PAYSTACK_SECRET_KEY}});
  const v=await verify.json() as any;
  if(!verify.ok||!v.status||v.data?.status!=="success"||v.data?.reference!==reference||v.data?.amount!==10000||v.data?.currency!=="KES"||String(v.data?.metadata?.user_id||"")!==String(payment.user_id))return json({error:"Paystack verification did not match this activation payment"},400);
  await activate(env,reference,String(v.data.id));
 }
 return json({received:true});
}
try{const who=await identity(req,env);
if(path==="/api/register"&&req.method==="POST"){const body=await req.json<any>(),existing=await user(env,who.uid);if(existing)return json({profile:existing});const ref=String(body.referralCode||"").toUpperCase();const referrer=ref?await env.DB.prepare("SELECT id FROM users WHERE referral_code=?").bind(ref).first<any>():null;const uid=id(),refcode=code();await env.DB.prepare("INSERT INTO users(id,firebase_uid,email,display_name,referral_code,referred_by_user_id) VALUES(?,?,?,?,?,?)").bind(uid,who.uid,who.email,String(body.displayName||who.name||"").slice(0,80),refcode,referrer?.id||null).run();if(referrer&&referrer.id!==uid)await env.DB.prepare("INSERT OR IGNORE INTO referrals(id,referrer_user_id,referred_user_id,referral_code,status,reward_cents) VALUES(?,?,?,?, 'pending_activation',700)").bind(id(),referrer.id,uid,ref).run();return json({profile:await user(env,who.uid)});}
const me=await user(env,who.uid);if(!me)return json({error:"Account profile not found. Please register again."},404);
if(path==="/api/me"){await resetInactiveBalance(env,me);return json({profile:await user(env,who.uid)});}
if(path==="/api/payment/initiate"&&req.method==="POST"){if(me.activated)return json({message:"Your account is already activated."});const pending=await env.DB.prepare("SELECT reference,created_at,created_at<=datetime('now','-3 minutes') AS expired FROM payments WHERE user_id=? AND status='pending' ORDER BY created_at DESC LIMIT 1").bind(me.id).first<any>();if(pending){if(pending.expired){const vr=await fetch("https://api.paystack.co/transaction/verify/"+encodeURIComponent(pending.reference),{headers:{Authorization:"Bearer "+env.PAYSTACK_SECRET_KEY}});const verified=await vr.json() as any;if(vr.ok&&verified.status&&verified.data?.status==="success"&&verified.data?.reference===pending.reference&&verified.data?.amount===10000&&verified.data?.currency==="KES"&&String(verified.data?.metadata?.user_id||"")===String(me.id)){await activate(env,pending.reference,String(verified.data.id));return json({message:"Your M-Pesa payment was verified and your account is activated. Refresh your dashboard."});}if(vr.ok&&verified.status&&["failed","abandoned"].includes(String(verified.data?.status))){await env.DB.prepare("UPDATE payments SET status=? WHERE reference=? AND status='pending'").bind(verified.data.status==="abandoned"?"abandoned":"failed",pending.reference).run();}else return json({error:"Your previous M-Pesa request is still being checked. Please wait; a second payment prompt has not been created.",reference:pending.reference},409);}else return json({error:"A payment request is already pending. Complete the M-Pesa prompt before requesting another.",reference:pending.reference},409);}const body=await req.json<any>(),phone=String(body.phone||"").replace(/\D/g,"");if(!/^254[17]\d{8}$/.test(phone))return json({error:"Enter a valid Kenyan M-Pesa number beginning 254."},400);const reference="MH-"+crypto.randomUUID();await env.DB.prepare("INSERT INTO payments(reference,user_id,amount_minor,currency,phone_number,status) VALUES(?,?,10000,'KES',?,'pending')").bind(reference,me.id,phone).run();const response=await fetch("https://api.paystack.co/charge",{method:"POST",headers:{"Authorization":"Bearer "+env.PAYSTACK_SECRET_KEY,"Content-Type":"application/json"},body:JSON.stringify({email:who.email,amount:"10000",currency:"KES",reference,mobile_money:{phone,provider:"mpesa"},metadata:{user_id:me.id,purpose:"mutah_hash_activation"}})}).then(r=>r.json()) as any;if(!response.status||response.data?.reference!==reference){await env.DB.prepare("UPDATE payments SET status='failed' WHERE reference=? AND status='pending'").bind(reference).run();return json({error:response.message||"Paystack did not create the expected M-Pesa charge."},400);}if(response.data?.id)await env.DB.prepare("UPDATE payments SET paystack_transaction_id=? WHERE reference=? AND status='pending'").bind(String(response.data.id),reference).run();return json({message:response.data?.display_text||"M-Pesa prompt requested. Check your phone and approve the KSh 100 payment. Activation happens only after Paystack confirms payment.",reference,payment_status:response.data?.status||"pending"});}
if(path==="/api/hash/start"&&req.method==="POST"){
 if(!me.activated)return json({error:"Activate your account first."},403);
 await resetInactiveBalance(env,me);
 const fresh=await user(env,who.uid);
 if(fresh.session_active)return json({error:fresh.session_ends_at&&Date.parse(fresh.session_ends_at)<=now?"Your 24-hour session is complete. Claim its reward before starting another.":"Your 24-hour session is already active."},409);
 const end=new Date(now+24*3600000).toISOString();
 const started=await env.DB.prepare("UPDATE users SET session_active=1,session_ends_at=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND session_active=0").bind(end,me.id).run();
 if(!started.meta.changes)return json({error:"A HASH session is already active. Refresh and check its status."},409);
 return json({message:"HASH session started. Return after the 24-hour session ends.",session_ends_at:end});
}
if(path==="/api/hash/claim"&&req.method==="POST"){
 if(!me.activated)return json({error:"Activate your account first."},403);
 const now=Date.now(),end=me.session_ends_at?Date.parse(me.session_ends_at):0;
 if(!me.session_active||!end||now<end)return json({error:"Your 24-hour HASH session has not finished yet."},409);
 const claimRef="HASH-"+me.id+"-"+end;
 const results=await env.DB.batch([
  env.DB.prepare("UPDATE users SET mining_balance_sats=mining_balance_sats+1500,session_active=0,last_hash_at=CURRENT_TIMESTAMP,session_ends_at=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=? AND session_active=1 AND julianday(session_ends_at)<=julianday('now')").bind(me.id),
  env.DB.prepare("INSERT OR IGNORE INTO ledger(id,user_id,entry_type,amount_sats,status,reference,note) SELECT ?,?,'hash_reward',1500,'completed',?,'Virtual HASH cycle reward' FROM users WHERE id=? AND session_active=0 AND last_hash_at>=datetime('now','-2 seconds')").bind(id(),me.id,claimRef,me.id)
 ]);
 if(!results[0].meta.changes)return json({error:"This HASH session was already claimed or has not finished."},409);
 return json({message:"0.000015 virtual BTC units credited. Any eventual payout is manual review."});
}
if(path==="/api/withdrawals"&&req.method==="POST"){
 const body=await req.json<any>(),asset=body.asset==="BTC"?"BTC":body.asset==="USD"?"USD":null,destination=String(body.destination||"").trim();
 if(!asset)return json({error:"Choose a valid reward balance."},400);
 if(!destination||destination.length>200)return json({error:"Enter valid payout destination details."},400);
 if(asset==="BTC"&&!me.activated)return json({error:"Activate your account before requesting a HASH withdrawal."},403);
 const requestId=id();
 const result=await env.DB.prepare("INSERT INTO withdrawals(id,user_id,asset,amount_sats,amount_cents,destination,status) SELECT ?,u.id,?,CASE WHEN ?='BTC' THEN u.mining_balance_sats-COALESCE((SELECT SUM(amount_sats) FROM withdrawals WHERE user_id=u.id AND asset='BTC' AND status IN ('pending','approved')),0) ELSE 0 END,CASE WHEN ?='USD' THEN u.referral_balance_cents-COALESCE((SELECT SUM(amount_cents) FROM withdrawals WHERE user_id=u.id AND asset='USD' AND status IN ('pending','approved')),0) ELSE 0 END,?,'pending' FROM users u WHERE u.id=? AND (CASE WHEN ?='BTC' THEN u.mining_balance_sats-COALESCE((SELECT SUM(amount_sats) FROM withdrawals WHERE user_id=u.id AND asset='BTC' AND status IN ('pending','approved')),0) ELSE u.referral_balance_cents-COALESCE((SELECT SUM(amount_cents) FROM withdrawals WHERE user_id=u.id AND asset='USD' AND status IN ('pending','approved')),0) END)>0").bind(requestId,asset,asset,asset,destination,me.id,asset).run();
 if(!result.meta.changes)return json({error:"There is no unreserved balance available for this withdrawal."},400);
 return json({message:"Withdrawal request submitted for manual review. Payment is not automatic or guaranteed.",request_id:requestId});
}
if(path==="/api/admin/dashboard"&&req.method==="GET"){
 if(who.email!==env.ADMIN_EMAIL.toLowerCase())return json({error:"Admin access denied."},403);
 const [summary,users,payments,withdrawals]=await Promise.all([
  env.DB.prepare("SELECT COUNT(*) AS total_users,COALESCE(SUM(activated),0) AS activated_users,COALESCE(SUM(mining_balance_sats),0) AS virtual_btc_sats,COALESCE(SUM(referral_balance_cents),0) AS referral_cents FROM users").first<any>(),
  env.DB.prepare("SELECT id,email,display_name,activated,status,referral_code,mining_balance_sats,referral_balance_cents,created_at FROM users ORDER BY created_at DESC LIMIT 100").all<any>(),
  env.DB.prepare("SELECT p.reference,p.user_id,u.email,p.amount_minor,p.currency,p.phone_number,p.status,p.created_at,p.paid_at FROM payments p JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC LIMIT 50").all<any>(),
  env.DB.prepare("SELECT w.id,w.user_id,w.asset,w.amount_sats,w.amount_cents,w.destination,w.status,w.requested_at,u.email FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.requested_at DESC LIMIT 100").all<any>()
 ]);
 return json({summary,users:users.results,payments:payments.results,withdrawals:withdrawals.results});
}
if(path==="/api/admin/withdrawals/action"&&req.method==="POST"){
 if(who.email!==env.ADMIN_EMAIL.toLowerCase())return json({error:"Admin access denied."},403);
 const body=await req.json<any>(),withdrawalId=String(body.id||""),action=String(body.action||"");
 if(!withdrawalId||!["approve","reject","paid"].includes(action))return json({error:"Invalid withdrawal action."},400);
 if(action==="approve"){const r=await env.DB.prepare("UPDATE withdrawals SET status='approved',reviewed_at=CURRENT_TIMESTAMP,admin_note=? WHERE id=? AND status='pending'").bind(String(body.note||"Approved for manual payout").slice(0,500),withdrawalId).run();if(!r.meta.changes)return json({error:"Only pending requests can be approved."},409);}
 if(action==="reject"){const r=await env.DB.prepare("UPDATE withdrawals SET status='rejected',reviewed_at=CURRENT_TIMESTAMP,admin_note=? WHERE id=? AND status IN ('pending','approved')").bind(String(body.note||"Rejected by admin").slice(0,500),withdrawalId).run();if(!r.meta.changes)return json({error:"Only pending or approved requests can be rejected."},409);}
 if(action==="paid"){
  const w=await env.DB.prepare("SELECT * FROM withdrawals WHERE id=? AND status='approved'").bind(withdrawalId).first<any>();
  if(!w)return json({error:"Only approved requests can be marked paid."},409);
  await env.DB.batch([
   env.DB.prepare("INSERT OR IGNORE INTO ledger(id,user_id,entry_type,amount_sats,amount_cents,status,reference,note) SELECT ?,user_id,'withdrawal_paid',-amount_sats,-amount_cents,'pending_debit',id,'Admin confirmed manual payout' FROM withdrawals WHERE id=? AND status='approved' AND EXISTS(SELECT 1 FROM users WHERE id=withdrawals.user_id AND ((withdrawals.asset='BTC' AND mining_balance_sats>=withdrawals.amount_sats) OR (withdrawals.asset='USD' AND referral_balance_cents>=withdrawals.amount_cents)))").bind(id(),withdrawalId),
   env.DB.prepare("UPDATE users SET mining_balance_sats=mining_balance_sats+(SELECT amount_sats FROM ledger WHERE reference=? AND entry_type='withdrawal_paid' AND status='pending_debit'),referral_balance_cents=referral_balance_cents+(SELECT amount_cents FROM ledger WHERE reference=? AND entry_type='withdrawal_paid' AND status='pending_debit'),updated_at=CURRENT_TIMESTAMP WHERE id=(SELECT user_id FROM ledger WHERE reference=? AND entry_type='withdrawal_paid' AND status='pending_debit')").bind(withdrawalId,withdrawalId,withdrawalId),
   env.DB.prepare("UPDATE ledger SET status='completed' WHERE reference=? AND entry_type='withdrawal_paid' AND status='pending_debit'").bind(withdrawalId),
   env.DB.prepare("UPDATE withdrawals SET status='paid',paid_at=CURRENT_TIMESTAMP,reviewed_at=COALESCE(reviewed_at,CURRENT_TIMESTAMP),admin_note=? WHERE id=? AND status='approved' AND EXISTS(SELECT 1 FROM ledger WHERE reference=? AND entry_type='withdrawal_paid' AND status='completed')").bind(String(body.note||"Paid manually by admin").slice(0,500),withdrawalId,withdrawalId)
  ]);
  const done=await env.DB.prepare("SELECT status FROM withdrawals WHERE id=?").bind(withdrawalId).first<any>();
  if(done?.status!=="paid")return json({error:"Payout could not be recorded. Check the user's balance and request status."},409);
 }
 return json({message:"Withdrawal status updated.",withdrawal_id:withdrawalId,action});
}
return json({error:"Not found or not authorized."},404);
}catch(e){return json({error:e instanceof Error?e.message:"Unexpected server error"},401);}}
export default{fetch:handle};
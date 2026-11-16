export interface Env{DB:D1Database;FIREBASE_PROJECT_ID:string;ADMIN_EMAIL:string;PAYSTACK_SECRET_KEY:string}
const json=(data:unknown,status=200)=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json","access-control-allow-origin":"*","access-control-allow-headers":"authorization,content-type","access-control-allow-methods":"GET,POST,OPTIONS"}});
const b64=(s:string)=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0));
async function identity(req:Request,env:Env){const h=req.headers.get("authorization")||"";const token=h.startsWith("Bearer ")?h.slice(7):"";if(!token)throw new Error("Sign in required");const parts=token.split(".");if(parts.length!==3)throw new Error("Invalid login token");const header=JSON.parse(new TextDecoder().decode(b64(parts[0]))),claims=JSON.parse(new TextDecoder().decode(b64(parts[1])));if(claims.aud!==env.FIREBASE_PROJECT_ID||claims.iss!=="https://securetoken.google.com/"+env.FIREBASE_PROJECT_ID||claims.exp<Date.now()/1000||!claims.sub)throw new Error("Login token expired or invalid");const keys=await fetch("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com").then(r=>r.json()) as {keys:Array<JsonWebKey & {kid:string}>};const jwk=keys.keys.find(k=>k.kid===header.kid);if(!jwk)throw new Error("Unable to verify login token");const key=await crypto.subtle.importKey("jwk",jwk,{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["verify"]);const ok=await crypto.subtle.verify("RSASSA-PKCS1-v1_5",key,b64(parts[2]),new TextEncoder().encode(parts[0]+"."+parts[1]));if(!ok)throw new Error("Invalid login signature");return{uid:claims.sub as string,email:String(claims.email||"").toLowerCase(),emailVerified:claims.email_verified===true,name:String(claims.name||"")};}
const id=()=>crypto.randomUUID();const code=()=>crypto.randomUUID().replace(/-/g,"").slice(0,10).toUpperCase();
async function user(env:Env,uid:string){return env.DB.prepare("SELECT * FROM users WHERE firebase_uid=?").bind(uid).first<any>();}
async function resetInactiveBalance(env:Env,me:any){
 if(me.session_active)return;
 const anchor=me.last_hash_at||me.activated_at;
 if(!anchor||Date.now()-Date.parse(anchor)<=72*3600000)return;
 const reservedRow=await env.DB.prepare("SELECT COALESCE(SUM(amount_sats),0) AS reserved FROM withdrawals WHERE user_id=? AND asset='BTC' AND status IN ('pending','approved')").bind(me.id).first<any>();
 const reserved=Number(reservedRow?.reserved||0),balance=Number(me.mining_balance_sats||0),resetAmount=Math.max(0,balance-reserved);
 const resetRef="INACTIVITY-"+me.id+"-"+Date.parse(anchor);
 const update=await env.DB.prepare("UPDATE users SET mining_balance_sats=?,session_active=0,session_ends_at=NULL,last_inactivity_reset_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=? AND COALESCE(last_hash_at,activated_at)=? AND julianday(COALESCE(last_hash_at,activated_at))<=julianday('now','-72 hours') AND (last_inactivity_reset_at IS NULL OR julianday(last_inactivity_reset_at)<julianday(?))").bind(reserved,me.id,anchor,anchor).run();
 if(update.meta.changes&&resetAmount>0){
  await env.DB.prepare("INSERT OR IGNORE INTO ledger(id,user_id,entry_type,amount_sats,status,reference,note) VALUES(?,?, 'inactivity_reset',?,'completed',?,'Unreserved HASH rewards reset after 72 consecutive hours without a successful HASH claim')").bind(id(),me.id,-resetAmount,resetRef).run();
 }
}
const HASH_SESSION_REWARD_SATS=15000;
const HASH_SESSION_INTERVAL_MS=300000;
// Kenya uses East Africa Time (UTC+3) year-round. Every AIRDROP session ends
// at the next midnight in Kenya, regardless of when the user starts it.
function nextKenyaMidnight(timestamp:number){
 const kenyaNow=new Date(timestamp+3*60*60*1000);
 const midnightUtc=Date.UTC(kenyaNow.getUTCFullYear(),kenyaNow.getUTCMonth(),kenyaNow.getUTCDate()+1);
 return midnightUtc-3*60*60*1000;
}
async function accrueHashSession(env:Env,me:any){
 if(!me.session_active||!me.session_started_at)return;
 const started=Date.parse(me.session_started_at);
 if(!Number.isFinite(started))return;
 const ends=nextKenyaMidnight(started);
 const now=Date.now();
 const effectiveNow=Math.min(now,ends);
 const elapsed=Math.max(0,effectiveNow-started);
 const credited=Number(me.session_credited_sats||0);
 // Keep the existing 15,000-satoshi-equivalent-per-24-hours rate. Users who
 // start later receive only the proportional amount for time until midnight.
 const target=Math.floor(elapsed*HASH_SESSION_REWARD_SATS/86400000);
 const finished=now>=ends;
 if(target<=credited&&!finished){await env.DB.prepare("UPDATE users SET session_ends_at=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND session_active=1 AND session_started_at=?").bind(new Date(ends).toISOString(),me.id,me.session_started_at).run();return;}
 const delta=Math.max(0,target-credited);
 const updated=await env.DB.prepare("UPDATE users SET mining_balance_sats=mining_balance_sats+?,session_credited_sats=?,session_active=CASE WHEN ?=1 THEN 0 ELSE 1 END,session_ends_at=CASE WHEN ?=1 THEN NULL ELSE ? END,session_started_at=CASE WHEN ?=1 THEN NULL ELSE session_started_at END,last_hash_at=CASE WHEN ?=1 THEN CURRENT_TIMESTAMP ELSE last_hash_at END,updated_at=CURRENT_TIMESTAMP WHERE id=? AND session_active=1 AND session_credited_sats=? AND session_started_at=?").bind(delta,target,finished?1:0,finished?1:0,new Date(ends).toISOString(),finished?1:0,finished?1:0,me.id,credited,me.session_started_at).run();
 if(updated.meta.changes&&delta>0){
  const ref="HASH-SESSION-"+me.id+"-"+started+"-"+Math.floor(effectiveNow/HASH_SESSION_INTERVAL_MS);
  await env.DB.prepare("INSERT OR IGNORE INTO ledger(id,user_id,entry_type,amount_sats,status,reference,note) VALUES(?,?, 'hash_reward',?,'completed',?,'Proportional AIRDROP reward accrued until Kenya midnight')").bind(id(),me.id,delta,ref).run();
 }
}
async function activate(env:Env,reference:string,transactionId:string){
 const p=await env.DB.prepare("SELECT * FROM payments WHERE reference=?").bind(reference).first<any>();
 if(!p)throw new Error("Payment reference not found");
 if(p.amount_minor!==10000||p.currency!=="KES")throw new Error("Payment amount or currency mismatch");
 await env.DB.batch([
  env.DB.prepare("UPDATE payments SET status='success',paystack_transaction_id=COALESCE(paystack_transaction_id,?),paid_at=COALESCE(paid_at,CURRENT_TIMESTAMP),verified_at=CURRENT_TIMESTAMP WHERE reference=? AND status IN ('pending','failed','abandoned','success') AND amount_minor=10000 AND currency='KES'").bind(transactionId,reference),
  env.DB.prepare("UPDATE users SET activated=1,activated_at=COALESCE(activated_at,CURRENT_TIMESTAMP),status='active',updated_at=CURRENT_TIMESTAMP WHERE id=? AND EXISTS(SELECT 1 FROM payments WHERE reference=? AND status='success')").bind(p.user_id,reference),
  env.DB.prepare("INSERT OR IGNORE INTO referrals(id,referrer_user_id,referred_user_id,referral_code,status,reward_cents) SELECT lower(hex(randomblob(16))),u.referred_by_user_id,u.id,ref.referral_code,'pending_activation',700 FROM users u JOIN users ref ON ref.id=u.referred_by_user_id WHERE u.id=? AND u.referred_by_user_id IS NOT NULL AND EXISTS(SELECT 1 FROM payments WHERE reference=? AND status='success')").bind(p.user_id,reference),
  env.DB.prepare("UPDATE referrals SET status='rewarded',activation_reference=? WHERE referred_user_id=? AND status='pending_activation' AND EXISTS(SELECT 1 FROM payments WHERE reference=? AND status='success')").bind(reference,p.user_id,reference)
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
if(path==="/api/register"&&req.method==="POST"){const body=await req.json<any>(),existing=await user(env,who.uid);if(existing)return json({profile:existing});if(body.guidelinesAccepted!==true)return json({error:"Registration blocked: you must accept the Mutah Hash App & Community Guidelines."},400);const version=String(body.guidelinesVersion||"");if(version!=="2026-11-15-v3")return json({error:"The guidelines version is outdated or invalid. Refresh the app and review the current guidelines before registering."},409);if(!String(body.displayName||"").trim())return json({error:"Enter your full name before registering."},400);const ref=String(body.referralCode||"").trim().toUpperCase();const referrer=ref?await env.DB.prepare("SELECT id FROM users WHERE referral_code=?").bind(ref).first<any>():null;if(ref&&!referrer)return json({error:"This referral link is invalid. Please reopen the referral link shared with you and register again."},400);const uid=id(),refcode=code();await env.DB.batch([env.DB.prepare("INSERT INTO users(id,firebase_uid,email,display_name,referral_code,referred_by_user_id) VALUES(?,?,?,?,?,?)").bind(uid,who.uid,who.email,String(body.displayName||who.name||"").slice(0,80),refcode,referrer?.id||null),env.DB.prepare("INSERT INTO policy_consents(user_id,guidelines_version,accepted_at) VALUES(?,?,CURRENT_TIMESTAMP)").bind(uid,version)]);if(referrer&&referrer.id!==uid)await env.DB.prepare("INSERT OR IGNORE INTO referrals(id,referrer_user_id,referred_user_id,referral_code,status,reward_cents) VALUES(?,?,?,?, 'pending_activation',700)").bind(id(),referrer.id,uid,ref).run();return json({profile:await user(env,who.uid)});}
let me=await user(env,who.uid);if(!me)return json({error:"Account profile not found. Please register again."},404);if(me.status==="suspended")return json({error:"This account has been blocked from Mutah Hash. Contact support for a review. "+String(me.block_reason||"")},403);await resetInactiveBalance(env,me);me=await user(env,who.uid);await accrueHashSession(env,me);me=await user(env,who.uid);
if(path==="/api/me"){await resetInactiveBalance(env,me);await env.DB.prepare("INSERT OR IGNORE INTO referrals(id,referrer_user_id,referred_user_id,referral_code,status,reward_cents) SELECT lower(hex(randomblob(16))),u.referred_by_user_id,u.id,ref.referral_code,'pending_activation',700 FROM users u JOIN users ref ON ref.id=u.referred_by_user_id WHERE u.activated=0 AND NOT EXISTS(SELECT 1 FROM referrals r WHERE r.referred_user_id=u.id)").run();const profile=await user(env,who.uid);const qualified=await env.DB.prepare("SELECT COUNT(*) AS count FROM referrals r JOIN users u ON u.id=r.referred_user_id WHERE r.referrer_user_id=? AND r.status IN ('qualified','rewarded') AND u.activated=1").bind(me.id).first<any>();const referralStats=await env.DB.prepare("SELECT COUNT(*) AS total,COALESCE(SUM(CASE WHEN u.activated=0 THEN 1 ELSE 0 END),0) AS pending,COALESCE(SUM(CASE WHEN u.activated=1 THEN 1 ELSE 0 END),0) AS activated FROM users u WHERE u.referred_by_user_id=?").bind(me.id).first<any>();return json(profile.activated?{profile,qualified_referrals:Number(qualified?.count||0),total_referrals:Number(referralStats?.total||0),pending_referrals:Number(referralStats?.pending||0),activated_referrals:Number(referralStats?.activated||0),required_referrals:1}:{profile:{...profile,referral_code:"",referred_by_user_id:null},qualified_referrals:0,total_referrals:0,pending_referrals:0,activated_referrals:0});}
if(path==="/api/payment/status"&&req.method==="GET"){
 const reference=String(url.searchParams.get("reference")||"").trim();
 if(!reference)return json({error:"Payment reference is required."},400);
 const payment=await env.DB.prepare("SELECT * FROM payments WHERE reference=? AND user_id=?").bind(reference,me.id).first<any>();
 if(!payment)return json({error:"Payment record not found for this account."},404);
 if(payment.status==="success"){await activate(env,reference,String(payment.paystack_transaction_id||"PAYSTACK-VERIFIED"));const latest=await user(env,who.uid);return json({status:"success",activated:!!latest?.activated,message:latest?.activated?"Payment successful. Your account is activated.":"Payment is verified; account activation is being completed. Refresh shortly."});}
 const vr=await fetch("https://api.paystack.co/transaction/verify/"+encodeURIComponent(reference),{headers:{Authorization:"Bearer "+env.PAYSTACK_SECRET_KEY}});
 const verified=await vr.json() as any;
 if(vr.ok&&verified.status&&verified.data?.status==="success"){
  if(verified.data?.reference!==reference||verified.data?.amount!==10000||verified.data?.currency!=="KES"||String(verified.data?.metadata?.user_id||"")!==String(me.id))return json({error:"Payment verification details did not match this account. Activation was not granted."},409);
  await activate(env,reference,String(verified.data.id));
  return json({status:"success",activated:true,message:"Payment successful. Your account is now activated."});
 }
 const providerStatus=String(verified.data?.status||"").toLowerCase();
 if(vr.ok&&verified.status&&["failed","abandoned"].includes(providerStatus)){
  const status=providerStatus==="abandoned"?"abandoned":"failed";
  await env.DB.prepare("UPDATE payments SET status=? WHERE reference=? AND user_id=? AND status IN ('pending','failed','abandoned')").bind(status,reference,me.id).run();
  return json({status,activated:false,message:status==="abandoned"?"Payment was cancelled or abandoned. No payment was received. You can try again.":"Payment failed. No activation was granted. You can try again."});
 }
 return json({status:"pending",activated:false,message:"Waiting for M-Pesa/Paystack confirmation. Your account has not been activated yet."});
}
if(path==="/api/payment/initiate"&&req.method==="POST"){if(me.activated)return json({message:"Your account is already activated."});const pending=await env.DB.prepare("SELECT reference,created_at,created_at<=datetime('now','-3 minutes') AS expired FROM payments WHERE user_id=? AND status='pending' ORDER BY created_at DESC LIMIT 1").bind(me.id).first<any>();if(pending){if(pending.expired){const vr=await fetch("https://api.paystack.co/transaction/verify/"+encodeURIComponent(pending.reference),{headers:{Authorization:"Bearer "+env.PAYSTACK_SECRET_KEY}});const verified=await vr.json() as any;if(vr.ok&&verified.status&&verified.data?.status==="success"&&verified.data?.reference===pending.reference&&verified.data?.amount===10000&&verified.data?.currency==="KES"&&String(verified.data?.metadata?.user_id||"")===String(me.id)){await activate(env,pending.reference,String(verified.data.id));return json({message:"Your M-Pesa payment was verified and your account is activated. Refresh your dashboard."});}if(vr.ok&&verified.status&&["failed","abandoned"].includes(String(verified.data?.status))){await env.DB.prepare("UPDATE payments SET status=? WHERE reference=? AND status='pending'").bind(verified.data.status==="abandoned"?"abandoned":"failed",pending.reference).run();}else return json({error:"Your previous M-Pesa request is still being checked. Please wait; a second payment prompt has not been created.",reference:pending.reference},409);}else return json({error:"A payment request is already pending. Complete the M-Pesa prompt before requesting another.",reference:pending.reference},409);}const body=await req.json<any>();let phone=String(body.phone||"").replace(/\D/g,"");if(phone.length===10&&phone.startsWith("0"))phone="254"+phone.slice(1);if(phone.length===9&&(phone.startsWith("7")||phone.startsWith("1")))phone="254"+phone;if(!/^254[17]\d{8}$/.test(phone))return json({error:"Enter a valid Kenyan M-Pesa number, for example 0712345678 or 254712345678."},400);const reference="MH-"+crypto.randomUUID();await env.DB.prepare("INSERT INTO payments(reference,user_id,amount_minor,currency,phone_number,status) VALUES(?,?,10000,'KES',?,'pending')").bind(reference,me.id,phone).run();const response=await fetch("https://api.paystack.co/charge",{method:"POST",headers:{"Authorization":"Bearer "+env.PAYSTACK_SECRET_KEY,"Content-Type":"application/json"},body:JSON.stringify({email:who.email,amount:"10000",currency:"KES",reference,mobile_money:{phone:"+"+phone,provider:"mpesa"},metadata:{user_id:me.id,purpose:"mutah_hash_activation"}})}).then(r=>r.json()) as any;if(!response.status||response.data?.reference!==reference||!["pay_offline","pending","success"].includes(String(response.data?.status||""))){await env.DB.prepare("UPDATE payments SET status='failed' WHERE reference=? AND status='pending'").bind(reference).run();const detail=String(response.message||response.data?.message||"Paystack did not confirm an M-Pesa charge request.");return json({error:"Paystack could not start the M-Pesa prompt: "+detail},400);}if(response.data?.id)await env.DB.prepare("UPDATE payments SET paystack_transaction_id=? WHERE reference=? AND status='pending'").bind(String(response.data.id),reference).run();return json({message:response.data?.display_text||"M-Pesa prompt requested. Check your phone and approve the KSh 100 payment. Activation happens only after Paystack confirms payment.",reference,payment_status:response.data?.status||"pending"});}
if(path==="/api/hash/start"&&req.method==="POST"){
 const now=Date.now();
 if(!me.activated)return json({error:"Activate your account first."},403);
 {
  // Enforce the one-successful-paid-referral requirement for every account,
  // including older accounts with previous HASH activity. Once qualified,
  // the referral remains valid for all future AIRDROP sessions.
  const qualified=await env.DB.prepare("SELECT COUNT(*) AS count FROM referrals r JOIN users u ON u.id=r.referred_user_id WHERE r.referrer_user_id=? AND r.status IN ('qualified','rewarded') AND u.activated=1").bind(me.id).first<any>();
  if(Number(qualified?.count||0)<1)return json({error:"Before starting AIRDROP, share your referral link with someone who registers and completes their own verified KSh 100 activation. You can invite as many people as you like; only one successful paid referral is required. Once qualified, you will not need to refer again."},403);
 }
 await resetInactiveBalance(env,me);
 const fresh=await user(env,who.uid);
 if(fresh.session_active)return json({error:fresh.session_ends_at&&Date.parse(fresh.session_ends_at)<=now?"Your 24-hour session is complete. Claim its reward before starting another.":"Your 24-hour session is already active."},409);
 const start=new Date(now).toISOString(),end=new Date(nextKenyaMidnight(now)).toISOString();
 const started=await env.DB.prepare("UPDATE users SET session_active=1,session_started_at=?,session_ends_at=?,session_credited_sats=0,updated_at=CURRENT_TIMESTAMP WHERE id=? AND session_active=0").bind(start,end,me.id).run();
 if(!started.meta.changes)return json({error:"AIRDROP is already active. Refresh and check its status."},409);
 return json({message:"AIRDROP started.",session_started_at:start,session_ends_at:end});
}
if(path==="/api/hash/claim"&&req.method==="POST"){
 return json({error:"There is no separate AIRDROP claim while a session is active. Start a new AIRDROP after the current session ends."},409);
}
if(path==="/api/early-withdrawals"&&req.method==="GET"){
 const rows=await env.DB.prepare("SELECT id,reason,payment_method,destination,document_name,document_mime,document_size,status,admin_reason,withdrawal_id,requested_at,reviewed_at FROM early_withdrawal_requests WHERE user_id=? ORDER BY requested_at DESC LIMIT 50").bind(me.id).all<any>();
 return json({requests:rows.results});
}
if(path==="/api/early-withdrawals"&&req.method==="POST"){
 if(!me.activated)return json({error:"Activate your account before requesting an early withdrawal."},403);
 const activationRaw=me.activated_at?String(me.activated_at):"";
 const activationDate=activationRaw?new Date(activationRaw.includes("T")?activationRaw:activationRaw.replace(" ","T")+"Z"):null;
 if(!activationDate||Number.isNaN(activationDate.getTime()))return json({error:"Your verified activation date is unavailable."},403);
 const opens=new Date(activationDate);opens.setMonth(opens.getMonth()+5);
 if(Date.now()>=opens.getTime())return json({error:"Your normal five-month withdrawal period has opened. Please use the standard withdrawal request form."},409);
 const body=await req.json<any>(),reason=String(body.reason||"").trim(),documentName=String(body.documentName||"").slice(0,180),documentMime=String(body.documentMime||""),documentBase64=String(body.documentBase64||""),paymentMethod=String(body.paymentMethod||""),destinationRaw=String(body.destination||"").trim();
 if(reason.length<20||reason.length>2000)return json({error:"Explain your reason in at least 20 characters and no more than 2,000 characters."},400);
 if(!["application/pdf","image/jpeg","image/png"].includes(documentMime)||!documentName||!documentBase64)return json({error:"Upload one PDF, JPG or PNG supporting document."},400);
 if(documentBase64.length>1400000)return json({error:"The supporting document must be 1 MB or smaller."},413);
 let bytes:Uint8Array;
 try{const raw=atob(documentBase64);if(raw.length>1024*1024)return json({error:"The supporting document must be 1 MB or smaller."},413);bytes=Uint8Array.from(raw,c=>c.charCodeAt(0));}catch{return json({error:"The uploaded document could not be read."},400);}
 let destination=destinationRaw;
 if(!destination||destination.length>200)return json({error:"Enter valid payment receiver details."},400);
 if(paymentMethod==="MPESA"||paymentMethod==="AIRTEL"){
  let digits=destination.replace(/\D/g,"");
  if(digits.length===10&&digits.startsWith("0"))digits="254"+digits.slice(1);
  if(digits.length===9&&(digits.startsWith("7")||digits.startsWith("1")))digits="254"+digits;
  if(!/^254[17]\d{8}$/.test(digits))return json({error:"Enter a valid Kenyan mobile-money number."},400);
  destination=digits;
 }else if(!["BSC","SEGWITBTC","BTC","ETH"].includes(paymentMethod))return json({error:"Choose M-Pesa, Airtel Money or a supported crypto network."},400);
 const existing=await env.DB.prepare("SELECT id FROM early_withdrawal_requests WHERE user_id=? AND status='pending' LIMIT 1").bind(me.id).first<any>();if(existing)return json({error:"You already have an early withdrawal request awaiting review."},409);
 const requestId=id();
 await env.DB.prepare("INSERT INTO early_withdrawal_requests(id,user_id,reason,payment_method,destination,document_name,document_mime,document_size,document_blob,status) VALUES(?,?,?,?,?,?,?,?,?,'pending')").bind(requestId,me.id,reason,paymentMethod,destination,documentName,documentMime,bytes.length,bytes).run();
 return json({message:"Your early withdrawal exception request and supporting document have been submitted for admin review. This is not approval or a payout.",request_id:requestId});
}
if(path.startsWith("/api/admin/early-withdrawals/")&&path.endsWith("/document")&&req.method==="GET"){
 if(who.email!==env.ADMIN_EMAIL.toLowerCase())return json({error:"Admin access denied."},403);
 const requestId=path.split("/")[4];
 const row=await env.DB.prepare("SELECT document_blob,document_mime,document_name FROM early_withdrawal_requests WHERE id=?").bind(requestId).first<any>();
 if(!row)return json({error:"Supporting document not found."},404);
 return new Response(row.document_blob,{headers:{"content-type":row.document_mime,"content-disposition":"inline; filename*=UTF-8''"+encodeURIComponent(row.document_name),"cache-control":"private, no-store","access-control-allow-origin":"*","access-control-allow-headers":"authorization,content-type"}});
}
if(path==="/api/withdrawals"&&req.method==="GET"){
 const rows=await env.DB.prepare("SELECT id,asset,amount_sats,amount_cents,destination,network,status,admin_note,requested_at,reviewed_at,paid_at FROM withdrawals WHERE user_id=? ORDER BY requested_at DESC LIMIT 100").bind(me.id).all<any>();
 return json({withdrawals:rows.results});
}
if(path==="/api/withdrawals"&&req.method==="POST"){
 const body=await req.json<any>(),asset=body.asset==="BTC"?"BTC":null,destinationRaw=String(body.destination||"").trim(),network=asset==="BTC"?String(body.network||""):"";
 if(!asset)return json({error:"Choose a valid reward balance."},400);
 if(!destinationRaw||destinationRaw.length>200)return json({error:"Enter valid payout destination details."},400);
 if(!asset||!me.activated)return json({error:"Activate your account before requesting a HASH withdrawal."},403);
 const activationRaw=me.activated_at?String(me.activated_at):"";
 const activationDate=activationRaw?new Date(activationRaw.includes("T")?activationRaw:activationRaw.replace(" ","T")+"Z"):null;
 if(!activationDate||Number.isNaN(activationDate.getTime()))return json({error:"Your verified activation date is unavailable. Please contact support before requesting a withdrawal."},403);
 const withdrawalOpensAt=new Date(activationDate);
 withdrawalOpensAt.setMonth(withdrawalOpensAt.getMonth()+5);
 if(Date.now()<withdrawalOpensAt.getTime())return json({error:"Withdrawal requests open five calendar months after your account activation date ("+withdrawalOpensAt.toISOString().slice(0,10)+")."},403);
 let destination=destinationRaw;
 if(network==="MPESA"||network==="AIRTEL"){
  let digits=destination.replace(/\\D/g,"");
  if(digits.length===10&&digits.startsWith("0"))digits="254"+digits.slice(1);
  if(digits.length===9&&(digits.startsWith("7")||digits.startsWith("1")))digits="254"+digits;
  if(!/^254[17]\\d{8}$/.test(digits))return json({error:"Enter a valid Kenyan mobile-money number, for example 0712345678 or 254712345678."},400);
  destination=digits;
 }else if(!["BSC","SEGWITBTC","BTC","ETH"].includes(network)){
  return json({error:"Choose M-Pesa, Airtel Money, or one of the supported crypto networks: BSC (BEP20), BTC, BTC SegWit, or ETH (ERC20)."},400);
 }
 const requestId=id();
 const result=await env.DB.prepare("INSERT INTO withdrawals(id,user_id,asset,amount_sats,amount_cents,destination,network,status) SELECT ?,u.id,?,CASE WHEN ?='BTC' THEN u.mining_balance_sats-COALESCE((SELECT SUM(amount_sats) FROM withdrawals WHERE user_id=u.id AND asset='BTC' AND status IN ('pending','approved')),0) ELSE 0 END,CASE WHEN ?='USD' THEN u.referral_balance_cents-COALESCE((SELECT SUM(amount_cents) FROM withdrawals WHERE user_id=u.id AND asset='USD' AND status IN ('pending','approved')),0) ELSE 0 END,?,?, 'pending' FROM users u WHERE u.id=? AND (CASE WHEN ?='BTC' THEN u.mining_balance_sats-COALESCE((SELECT SUM(amount_sats) FROM withdrawals WHERE user_id=u.id AND asset='BTC' AND status IN ('pending','approved')),0) ELSE u.referral_balance_cents-COALESCE((SELECT SUM(amount_cents) FROM withdrawals WHERE user_id=u.id AND asset='USD' AND status IN ('pending','approved')),0) END)>0").bind(requestId,asset,asset,asset,destination,network||null,me.id,asset).run();
 if(!result.meta.changes)return json({error:"There is no unreserved balance available for this withdrawal."},400);
 return json({message:"Withdrawal request submitted for manual review. Payment is not automatic or guaranteed.",request_id:requestId});
}
if(path==="/api/admin/dashboard"&&req.method==="GET"){
 if(who.email!==env.ADMIN_EMAIL.toLowerCase())return json({error:"Admin access denied."},403);
 const pending=await env.DB.prepare("SELECT reference,user_id,amount_minor,currency FROM payments WHERE status IN ('pending','failed','abandoned') ORDER BY created_at DESC LIMIT 50").all<any>();
 const paymentFlags:any[]=[];
 for(const p of pending.results){
  const vr=await fetch("https://api.paystack.co/transaction/verify/"+encodeURIComponent(p.reference),{headers:{Authorization:"Bearer "+env.PAYSTACK_SECRET_KEY}});
  const verified=await vr.json() as any;
  if(vr.ok&&verified.status&&verified.data?.status==="success"){
   const matches=verified.data?.reference===p.reference&&verified.data?.amount===10000&&verified.data?.currency==="KES"&&String(verified.data?.metadata?.user_id||"")===String(p.user_id);
   if(matches)await activate(env,p.reference,String(verified.data.id));
   else paymentFlags.push({reference:p.reference,user_id:p.user_id,reason:"Successful Paystack transaction does not match the expected KSh 100 activation details."});
  }else if(vr.ok&&verified.status&&["failed","abandoned"].includes(String(verified.data?.status))){
   await env.DB.prepare("UPDATE payments SET status=? WHERE reference=? AND status IN ('pending','failed','abandoned')").bind(verified.data.status==="abandoned"?"abandoned":"failed",p.reference).run();
  }
 }
 const page=Math.max(1,Math.min(1000,Number(url.searchParams.get("page")||1))),limit=50,offset=(page-1)*limit;
 const [summary,users,payments,withdrawals,referrals,earlyWithdrawals]=await Promise.all([
  env.DB.prepare("SELECT COUNT(*) AS total_users,COALESCE(SUM(activated),0) AS activated_users,COALESCE(SUM(mining_balance_sats),0) AS hash_rewards_sats,COALESCE(SUM(referral_balance_cents),0) AS referral_cents FROM users").first<any>(),
  env.DB.prepare("SELECT id,email,display_name,activated,status,block_reason,blocked_at,referral_code,mining_balance_sats,referral_balance_cents,created_at,activated_at FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?").bind(limit,offset).all<any>(),
  env.DB.prepare("SELECT p.reference,p.user_id,u.email,p.amount_minor,p.currency,p.phone_number,p.status,p.created_at,p.paid_at FROM payments p JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC LIMIT ? OFFSET ?").bind(limit,offset).all<any>(),
  env.DB.prepare("SELECT w.id,w.user_id,w.asset,w.amount_sats,w.amount_cents,w.destination,w.network,w.status,w.requested_at,u.email FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.requested_at DESC LIMIT ? OFFSET ?").bind(limit,offset).all<any>(),
  env.DB.prepare("SELECT r.id,r.referral_code,r.status,r.reward_cents,r.created_at,r.rewarded_at,referrer.email AS referrer_email,referred.email AS referred_email FROM referrals r JOIN users referrer ON referrer.id=r.referrer_user_id JOIN users referred ON referred.id=r.referred_user_id ORDER BY r.created_at DESC LIMIT ? OFFSET ?").bind(limit,offset).all<any>(),
  env.DB.prepare("SELECT e.id,e.user_id,e.reason,e.payment_method,e.destination,e.document_name,e.document_mime,e.document_size,e.status,e.admin_reason,e.withdrawal_id,e.requested_at,e.reviewed_at,u.email,u.display_name FROM early_withdrawal_requests e JOIN users u ON u.id=e.user_id ORDER BY e.requested_at DESC LIMIT ? OFFSET ?").bind(limit,offset).all<any>()
 ]);
 return json({summary,users:users.results,payments:payments.results,withdrawals:withdrawals.results,referrals:referrals.results,early_withdrawals:earlyWithdrawals.results,payment_flags:paymentFlags,page,page_size:limit});
}
if(path==="/api/admin/users/action"&&req.method==="POST"){
 if(who.email!==env.ADMIN_EMAIL.toLowerCase())return json({error:"Admin access denied."},403);
 const body=await req.json<any>(),userId=String(body.id||""),action=String(body.action||"");
 if(!userId||!["activate","suspend","restore","block"].includes(action))return json({error:"Invalid account action."},400);
 if(action==="block"){const reason=String(body.reason||"").trim();if(userId===me.id)return json({error:"You cannot block the administrator account currently in use."},400);if(reason.length<5||reason.length>500)return json({error:"A clear reason of 5 to 500 characters is required to block an account."},400);const r=await env.DB.prepare("UPDATE users SET status='suspended',block_reason=?,blocked_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(reason,userId).run();if(!r.meta.changes)return json({error:"Account not found."},404);return json({message:"Account blocked. The user will be signed out and blocked from platform requests.",user_id:userId,action});}
 if(action==="activate"){
  const payment=await env.DB.prepare("SELECT reference,paystack_transaction_id FROM payments WHERE user_id=? AND status='success' AND amount_minor=10000 AND currency='KES' ORDER BY paid_at DESC LIMIT 1").bind(userId).first<any>();
  if(!payment)return json({error:"This account cannot be activated until a successful KSh 100 payment is verified."},409);
  await activate(env,String(payment.reference),String(payment.paystack_transaction_id||"ADMIN-VERIFIED"));
 }
 if(action==="suspend"){
  const r=await env.DB.prepare("UPDATE users SET status='suspended',updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(userId).run();
  if(!r.meta.changes)return json({error:"Account not found."},404);
 }
 if(action==="restore"){
  const r=await env.DB.prepare("UPDATE users SET status=CASE WHEN activated=1 THEN 'active' ELSE 'pending' END,block_reason=NULL,blocked_at=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='suspended'").bind(userId).run();
  if(!r.meta.changes)return json({error:"Only suspended accounts can be restored."},409);
 }
 return json({message:"Account status updated.",user_id:userId,action});
}
if(path==="/api/admin/early-withdrawals/action"&&req.method==="POST"){
 if(who.email!==env.ADMIN_EMAIL.toLowerCase())return json({error:"Admin access denied."},403);
 const body=await req.json<any>(),requestId=String(body.id||""),action=String(body.action||""),reason=String(body.reason||"").trim();
 if(!requestId||!["accept","decline"].includes(action))return json({error:"Invalid early withdrawal review action."},400);
 if(reason.length<3||reason.length>1000)return json({error:"A review reason of 3 to 1,000 characters is required."},400);
 const request=await env.DB.prepare("SELECT * FROM early_withdrawal_requests WHERE id=? AND status='pending'").bind(requestId).first<any>();
 if(!request)return json({error:"Only pending early withdrawal requests can be reviewed."},409);
 if(action==="decline"){
  await env.DB.prepare("UPDATE early_withdrawal_requests SET status='declined',admin_reason=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'").bind(reason,requestId).run();
  return json({message:"Early withdrawal request declined and the reason saved.",request_id:requestId});
 }
 const withdrawalId=id();
 const availableSql="u.mining_balance_sats-COALESCE((SELECT SUM(amount_sats) FROM withdrawals WHERE user_id=u.id AND asset='BTC' AND status IN ('pending','approved')),0)";
 const results=await env.DB.batch([
  env.DB.prepare("INSERT INTO withdrawals(id,user_id,asset,amount_sats,amount_cents,destination,network,status,admin_note,reviewed_at) SELECT ?,u.id,'BTC',CAST(("+availableSql+")/2 AS INTEGER),0,?,?, 'approved',?,CURRENT_TIMESTAMP FROM users u WHERE u.id=? AND u.activated=1 AND ("+availableSql+")>=2").bind(withdrawalId,request.destination,request.payment_method,reason,request.user_id),
  env.DB.prepare("INSERT INTO ledger(id,user_id,entry_type,amount_sats,amount_cents,status,reference,note) SELECT ?,w.user_id,'early_withdrawal_fee',-(u.mining_balance_sats-COALESCE((SELECT SUM(amount_sats) FROM withdrawals WHERE user_id=u.id AND asset='BTC' AND status IN ('pending','approved')),0)),0,'completed',?,'50% early-withdrawal deduction applied when admin approved the exception' FROM withdrawals w JOIN users u ON u.id=w.user_id WHERE w.id=? AND w.status='approved' AND u.mining_balance_sats-COALESCE((SELECT SUM(amount_sats) FROM withdrawals WHERE user_id=u.id AND asset='BTC' AND status IN ('pending','approved')),0)>0").bind(id(),withdrawalId,withdrawalId),
  env.DB.prepare("UPDATE users SET mining_balance_sats=mining_balance_sats+(SELECT amount_sats FROM ledger WHERE reference=? AND entry_type='early_withdrawal_fee' AND status='completed'),updated_at=CURRENT_TIMESTAMP WHERE id=(SELECT user_id FROM withdrawals WHERE id=?) AND EXISTS(SELECT 1 FROM ledger WHERE reference=? AND entry_type='early_withdrawal_fee' AND status='completed')").bind(withdrawalId,withdrawalId,withdrawalId),
  env.DB.prepare("UPDATE early_withdrawal_requests SET status='accepted',admin_reason=?,withdrawal_id=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending' AND EXISTS(SELECT 1 FROM withdrawals WHERE id=? AND status='approved')").bind(reason,withdrawalId,requestId,withdrawalId)
 ]);
 if(!results[0].meta.changes)return json({error:"This user has no sufficient unreserved HASH balance for an early payout request."},409);
 const accepted=await env.DB.prepare("SELECT status FROM early_withdrawal_requests WHERE id=?").bind(requestId).first<any>();
 if(accepted?.status!=="accepted")return json({error:"The early withdrawal could not be finalised. Please refresh and review the request status."},409);
 return json({message:"Early withdrawal approved. 50% of the available HASH balance has been reserved for manual payout and the remaining 50% has been deducted as the early-withdrawal fee.",request_id:requestId,withdrawal_id:withdrawalId});
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
export default{
 fetch:handle,
 scheduled(_controller:ScheduledController,env:Env,ctx:ExecutionContext){
  ctx.waitUntil((async()=>{
   const active=await env.DB.prepare("SELECT * FROM users WHERE session_active=1 AND session_started_at IS NOT NULL").all<any>();
   const rows=active.results||[];
   for(let i=0;i<rows.length;i+=50){
    await Promise.allSettled(rows.slice(i,i+50).map(me=>accrueHashSession(env,me)));
   }
  })());
 }
};
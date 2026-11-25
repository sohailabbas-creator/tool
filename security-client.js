(function(){
  'use strict';
  const original=window.fetch.bind(window);
  const processingTimers=new WeakMap();
  // Keep CAPTCHA time outside the tool's processing budget. The job still owns
  // a native timer, so existing completion/cancellation cleanup remains valid.
  window.llmProcessingTimer=function(job,callback,ms){
    const signal=job.controller.signal;
    if(signal.aborted)return;
    processingTimers.set(signal,()=>{job.timer=setTimeout(callback,ms);});
  };
  function send(input,init,signal){
    if(signal?.aborted)throw new DOMException('Aborted','AbortError');
    const start=signal&&processingTimers.get(signal);
    if(start){processingTimers.delete(signal);start();}
    return original(input,init);
  }
  let configPromise, scriptPromise, serial=Promise.resolve();
  // Slow SDK delivery and fresh challenge retries share this bounded budget.
  // Keep it separate from the processing timer, which starts only at POST.
  const verificationTimeoutMs=300000, sdkTimeoutMs=120000;
  const securityTimeoutMessage='Security check timed out. Please complete the verification and try again.';
  async function securityPhase(signal,task){
    if(signal?.aborted)throw new DOMException('Aborted','AbortError');
    const controller=new AbortController();
    const started=Date.now();
    let timer,abort;
    const cancelled=new Promise((_,reject)=>{
      abort=()=>{reject(new DOMException('Aborted','AbortError'));controller.abort();};
      signal?.addEventListener('abort',abort,{once:true});
      // Bound config loading and the widget queue as well as human interaction.
      timer=setTimeout(()=>{
        console.warn('Turnstile verification', {code:'client_deadline',reason:'verification_timeout',elapsedMs:Date.now()-started});
        reject(Error(securityTimeoutMessage));controller.abort();
      },verificationTimeoutMs);
    });
    try{return await Promise.race([cancelled,task(controller.signal)]);}
    finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);}
  }
  function config(){
    // Serialize first-session initialization across tabs where Web Locks is available.
    const request=()=>original('/tools/api/security/config',{cache:'no-store'});
    if(!configPromise)configPromise=(navigator.locks?navigator.locks.request('llm-session-init',request):request()).then(r=>{
      if(!r.ok)throw Error('Security verification is temporarily unavailable.');return r.json();
    }).catch(e=>{configPromise=null;throw e;});
    return configPromise;
  }
  function load(signal){
    if(!scriptPromise)scriptPromise=new Promise((resolve,reject)=>{
      if(typeof window.turnstile?.render==='function'){resolve();return;}
      const script=document.createElement('script');
      // Dynamically inserted scripts are async. Turnstile.ready() rejects that
      // loading mode; the SDK's explicit onload callback signals readiness.
      const callback='__llmTurnstileLoaded';
      window[callback]=()=>{
        if(typeof window.turnstile?.render!=='function'){script.onerror();return;}
        delete window[callback];resolve();
      };
      script.src='https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload='+callback;
      script.async=true;
      script.onerror=()=>{delete window[callback];script.remove();reject(Error('Security check could not load. Please try again.'));};
      document.head.append(script);
    }).catch(error=>{scriptPromise=null;throw error;});
    // A slow script may still execute after a timeout. Keep that single load;
    // only a definitive load error permits inserting a replacement script.
    return new Promise((resolve,reject)=>{
      let timer;
      const started=Date.now();
      const finish=(error)=>{clearTimeout(timer);signal?.removeEventListener('abort',abort);error?reject(error):resolve();};
      const abort=()=>finish(new DOMException('Aborted','AbortError'));
      signal?.addEventListener('abort',abort,{once:true});
      timer=setTimeout(()=>{
        console.warn('Turnstile verification', {code:'client_sdk_deadline',reason:'sdk_timeout',elapsedMs:Date.now()-started});
        finish(Error('Security check could not load. Please try again.'));
      },sdkTimeoutMs);
      scriptPromise.then(()=>finish(),finish);
      if(signal?.aborted)abort();
    });
  }
  async function token(cfg,signal,anchor){
    if(signal?.aborted)throw new DOMException('Aborted','AbortError');
    const started=Date.now();
    await load(signal);
    for(let attempt=1;;attempt++){
      try{return await challenge(cfg,signal,anchor);}
      catch(error){
        const sdkTimeout=error.turnstileTimeout===true;
        if(!error.turnstileCode&&!sdkTimeout)throw error;
        // The timeout callback has no provider error code. Keep its local event
        // distinct from numeric SDK errors and the overall client deadline.
        const code=sdkTimeout?'sdk_timeout_callback':error.turnstileCode;
        // Only documented retryable errors qualify. A generic challenge failure
        // is not evidence of DNS failure or of any particular network cause.
        const retryable=sdkTimeout||/^(110600|110620|200500|300\d{3}|600\d{3})$/.test(code);
        const retrying=retryable&&attempt<3&&!signal?.aborted;
        const reason=sdkTimeout?'sdk_interaction_timeout':code==='200500'?'iframe_load':code==='110600'?'challenge_timeout':code==='110620'?'interaction_timeout':/^(300|600)/.test(code)?'challenge_failure':/^(110100|110110|110200|400020|400021|400070)$/.test(code)?'configuration':code==='200100'?'clock_or_cache':'unknown';
        // Fixed fields only: never log tokens, keys, user input or arbitrary SDK data.
        console.warn('Turnstile verification', {code,reason,attempt,elapsedMs:Date.now()-started,retrying});
        if(!retrying)throw error;
        // The failed widget has already been disposed outside its callback stack.
        // Own the delay instead of enabling SDK resets against removed widgets.
        // Challenge failures (including 300030) use the SDK's documented default
        // retry interval rather than restarting heavy work after only 1.5s on a
        // slow connection. This delay still belongs to the original 300s budget.
        const retryDelay=reason==='challenge_failure'?8000:attempt*1500;
        await new Promise((resolve,reject)=>{
          const abort=()=>{clearTimeout(timer);signal?.removeEventListener('abort',abort);reject(new DOMException('Aborted','AbortError'));};
          const timer=setTimeout(()=>{signal?.removeEventListener('abort',abort);resolve();},retryDelay);
          signal?.addEventListener('abort',abort,{once:true});
          if(signal?.aborted)abort();
        });
      }
    }
  }
  function challenge(cfg,signal,anchor){
    if(signal?.aborted)throw new DOMException('Aborted','AbortError');
    return new Promise((resolve,reject)=>{
      const panel=document.createElement('div');
      panel.setAttribute('data-turnstile-inline','');panel.setAttribute('aria-label','Security check');
      panel.style.cssText='max-width:100%;font:inherit;line-height:0;';
      const box=document.createElement('div');panel.append(box);
      if(anchor?.isConnected)anchor.insertAdjacentElement('afterend',panel);
      else (document.querySelector('#toolBody, #tool, main')||document.body).append(panel);
      let widget,done=false;
      const finish=(error,value)=>{
        if(done)return;done=true;signal?.removeEventListener('abort',abort);
        // Let render and the SDK callback stack finish before disposal. This
        // also captures the ID when render invokes a callback synchronously.
        Promise.resolve().then(()=>{
          try{if(widget!==undefined)window.turnstile.remove(widget);}
          catch(_){error=Error('Security check is unavailable. Please try again.');}
          finally{panel.remove();}
          error?reject(error):resolve(value);
        });
      };
      const abort=()=>finish(new DOMException('Aborted','AbortError'));
      signal?.addEventListener('abort',abort,{once:true});
      if(signal?.aborted){abort();return;}
      const theme=document.documentElement.getAttribute('data-theme');
      try{widget=window.turnstile.render(box,{sitekey:cfg.siteKey,action:'llm_generate',appearance:'interaction-only',size:'normal',theme:['light','dark'].includes(theme)?theme:'auto',
        // Each attempt owns one widget. Recovery creates a fresh widget, never
        // an SDK reset scheduled against a widget already removed by this client.
        retry:'never','refresh-expired':'never','refresh-timeout':'never',
        'before-interactive-callback':()=>{if(done)return;panel.style.marginBlock='8px';},
        'after-interactive-callback':()=>{if(done)return;panel.style.marginBlock='0';},
        callback:value=>finish(typeof value==='string'&&value.trim()?null:Error('Security check failed. Please try again.'),value),
        'error-callback':value=>{
          if(done)return true;
          const code=/^\d{6}$/.test(String(value))?String(value):'unknown';
          const error=Error('Security check failed. Please try again.'+(code==='unknown'?'':' (Code: '+code+')'));
          error.turnstileCode=code;finish(error);return true;
        },
        'timeout-callback':()=>{
          if(done)return;
          const error=Error(securityTimeoutMessage);
          error.turnstileTimeout=true;finish(error);
        },
        'expired-callback':()=>finish(Error('Security check expired. Please try again.'))});}
      catch(_){finish(Error('Security check is unavailable. Please try again.'));}
    });
  }
  window.fetch=async function(input,init){
    const url=new URL(input instanceof Request?input.url:String(input),location.href);
    const method=String(init?.method || (input instanceof Request?input.method:'GET')).toUpperCase();
    const route=url.pathname.replace(/^\/tools\/api\//,'/api/');
    const routes=['/api/grammar/check','/api/grammar/rewrite','/api/paraphrase','/api/paraphrase/variants','/api/paraphrase/word-alts','/api/translate','/api/student/generate','/api/citation'];
    if(url.origin!==location.origin||method!=='POST'||!routes.includes(route))return original(input,init);
    const focused=document.activeElement;
    const button=focused?.matches('button,input[type=submit]')?focused:document.querySelector('#runBtn, #goBtn, #checkBtn, #toolBody button.btn-primary');
    const anchor=button?.closest('.tool-actions, .opt-row, .panel-foot')||button;
    const signal=init?.signal||(input instanceof Request?input.signal:undefined);
    const value=await securityPhase(signal,async preparationSignal=>{
      const cfg=await config();
      if(preparationSignal.aborted)throw new DOMException('Aborted','AbortError');
      if(!cfg.enabled)return null;
      const pending=serial.then(()=>token(cfg,preparationSignal,anchor));serial=pending.catch(()=>{});
      return pending;
    });
    if(value===null)return send(input,init,signal);
    if(signal?.aborted)throw new DOMException('Aborted','AbortError');
    const headers=new Headers(init?.headers||(input instanceof Request?input.headers:undefined));
    headers.set('X-Turnstile-Token',value);
    return send(input,{...init,headers},signal);
  };
})();

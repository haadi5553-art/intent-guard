# Viva notes (Roman Urdu + English)

Sab se pehle ye code khud parho: `data.py` -> `agent.py` -> `defenses.py` -> `eval.py`. Viva mein har line explain karni hai.

## 30-second summary
LLM agent emails parh ke tools chalata hai. Attacker email mein chhupi instruction likh deta hai (indirect prompt injection)
aur agent attacker ka kaam kar deta hai (tool abuse). Maine 3-layer guard banaya: detector, intent gate, canary.
Pehle bina defense ke attack chalaye (ASR ~90%), phir defense ke saath (ASR ~0.1-0.5%), aur har layer ka alag
contribution (ablation) dikhaya.

## Flow of one scenario (`agent.run`)
1. Agent 3 emails parhta hai; detector har email check karta hai, suspicious ho to quarantine.
2. Agent user ka asli kaam plan karta hai (e.g. Ali ko reply).
3. Agar injected email dikh gayi to (90% probability) attacker ka kaam bhi plan karta hai.
4. Har tool call gate + canary se guzarti hai; sirf allowed calls execute hoti hain.
5. Attack success = attacker ki call execute ho gayi.

## Likely questions
- **Ye real LLM hai?** `eval.py` mein simulated agent hai (injection follow karne ki probability 0.9). Isse defense layers ka
  behaviour dikhta hai, kisi real model ka nahi. `llm_agent.py` + `eval_llm.py` real model (Ollama) ke liye hain; wo numbers
  report mein add karne hain (tum chala ke). Ye limitation khud pehle bata do.
- **Detector kya hai?** TF-IDF char+word n-grams + logistic regression. Proposal mein DeBERTa likha tha; HF sandbox mein
  unreachable tha, to classical model use kiya. `detector_hf.py` starter hai (untested).
- **Canonicalise kya karta hai?** Text ke saath base64-decoded, ROT13, reversed, un-leeted views jodta hai taake
  encoded injection bhi detector ko nazar aaye. Adaptive recall 46% -> 75%.
- **Gate kaise kaam karta hai?** `send_email`/`delete_file` tabhi chalti hai jab user ki apni request us tool ka keh rahi ho
  aur recipient/file ka naam request mein ho. Attacker ka address ya protected file request mein nahi hoti, to block.
- **Gate kab fail hota hai?** `leak_reply`: recipient asli hai (Ali), sirf body mein private notes hain. Gate pass kar deta hai
  (91% ASR gate akele ke saath); canary isay pakarta hai.
- **Canary kab fail hota hai?** Jab attack mein secret hota hi nahi (file delete) ya agent sirf secret ka ek hissa leak kare
  (humne 25% leaks mein partial notes rakhe).
- **Sab se kamzor result?** BIPIA public hold-out par detector recall ~32%: BIPIA attacks "Write a script..." jaisi
  seedhi tasks hain, injection jaisi nahi lagti. Isi liye text-based detection akeli kafi nahi.
- **False positives?** Hard-benign emails (URGENT, "ignore the earlier agenda") ke saath 0% FPR, lekin sample chhota hai (~600 emails).
- **Train/test leakage?** Detector alag wording sets aur alag BIPIA host emails/attack categories par test hota hai.
  Tool-abuse test wording attack families wahi hain, to wo score optimistic hai.
- **ASR / precision / recall / F1 / FPR kya hain?** ASR = kamyab attacks / total attacks. Precision = flagged mein asli injections.
  Recall = asli injections mein se pakri gayi. F1 = dono ka harmonic mean. FPR = benign jo ghalti se flag hui.
- **Latency?** Detector ~2.2 ms/email (3.7 ms canonicalise ke saath), gate+canary ~0.001 ms; LLM time shamil nahi.
- **Seeds kyun?** Randomness ka asar dekhne ke liye 5 seeds, mean ± sd. Draws fixed hain taake configs ka paired comparison ho.
- **Real deployment mein kya badlega?** Zyada tools, embeddings/LLM-based intent check, adaptive attacker, real model.

## Report mein add karna hai
Real-LLM table (`results_llm.md`) jab Ollama par chala lo; detector_hf ke numbers agar chalao.

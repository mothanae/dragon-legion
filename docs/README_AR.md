# دراجون ليجون — منصة اختبار الاختراق العالمية للأجهزة المحمولة

"الفيلق لا يركع لأي مفتاح؛ يختبر كل الأبواب حتى تصبح غير قابلة للكسر."

## الهندسة المعمارية

```
dragon_legion/
├── core/               # المنصة المركزية: الإعدادات، قاعدة البيانات، اكتشاف الأجهزة، خادم FastAPI، عامل Celery
├── modules/
│   ├── usb/            # الوحدة 1: بروتوكولات USB (ساهارا/فايرهاوس، BROM، فاستبوت، HID)
│   ├── ios/            # الوحدة 2: أجهزة آبل (checkm8، iMessage zero-click، GrayKey)
│   ├── blackberry/     # الوحدة 3: بلاكبيري (QNX RCE، محمل BB7، FIPS 140-2)
│   ├── symbian/        # الوحدة 4: سيمبيان ونوكيا (XIP ROM، SIS traversal، NK2، P2K)
│   ├── kaios/          # الوحدة 5: كايوس (بروتوكول التصحيح، WebAssembly sandbox escape)
│   ├── wireless/       # الوحدة 6: الهجمات اللاسلكية (واي-فاي، بلوتوث، NFC)
│   ├── cellular/       # الوحدة 6.4: النطاق الخلوي (SMS صامت، NAS fuzzer، خلية وهمية)
│   ├── physical/       # الوحدة 7: الهجمات الفيزيائية (EMFI، حقن الجهد، CPA، Chip-Off)
│   ├── crypto/         # الوحدة 8: فك التشفير (FDE brute-force، استغلال النواة، محللات FS)
│   ├── ai/             # الوحدة 9: الذكاء الاصطناعي (RL scheduler، VAE اكتشاف البروتوكول)
│   ├── supply_chain/   # الوحدة 10: سلسلة التوريد (خادم OTA وهمي، FPGA MITM)
│   └── post_exploitation/  # استخراج البيانات (نحت نظام الملفات، استخراج SQLite)
└── main.py             # نقطة الدخول CLI
```

## البداية السريعة

```bash
# التثبيت
sudo bash scripts/install_linux.sh

# تشغيل الخادم الرئيسي
python -m dragon_legion.main master

# تشغيل العامل (على لينكس مع الأجهزة المتصلة)
python -m dragon_legion.main worker

# تشخيص الأجهزة
python -m dragon_legion.main diagnose
```

## الوحدات المنفذة

| الوحدة | الاسم | الحالة | المتطلبات |
|--------|------|--------|-----------|
| 1 | هجمات USB السلكية | مكتمل | هاتف أندرويد مع صلاحيات روت |
| 2 | أجهزة iOS/آبل | مكتمل | جهاز A5-A11 في وضع DFU |
| 3 | بلاكبيري | مكتمل | جهاز BB10 أو BB7 |
| 4 | سيمبيان/نوكيا | مكتمل | هاتف سيمبيان أو نوكيا |
| 5 | KaiOS | مكتمل | جهاز KaiOS (نوكيا 8110/2720) |
| 6 | الهجمات اللاسلكية | مكتمل | محول Wi-Fi مع وضع المراقبة |
| 7 | الهجمات الفيزيائية | مكتمل | ChipSHOUTER، FPGA، راسم الذبذبات |
| 8 | فك التشفير | مكتمل | GPU مع CUDA |
| 9 | الذكاء الاصطناعي | مكتمل | PyTorch |
| 10 | سلسلة التوريد | مكتمل | FPGA، خادم DNS |
| 11 | التقارير والسجلات | مكتمل | PostgreSQL + TimescaleDB |

## الثغرات المنفذة (CVEs)

| CVE | الوحدة | الوصف | CVSS |
|-----|--------|-------|------|
| CVE-2019-14040 | USB Sahara | تجاوز سعة حزمة Hello | 7.8 |
| CVE-2020-3620 | USB Sahara | TOCTOU في مصادقة Read Data | 7.5 |
| CVE-2024-29745 | Fastboot | ذاكرة غير مهيأة AFU | 5.5 |
| CVE-2024-50302 | HID | تسرب ذاكرة kernel عبر GetReport | 6.2 |
| CVE-2017-9417 | Wi-Fi | Broadpwn — تجاوز كومة محلل beacon | 9.8 |
| CVE-2017-1000251 | Bluetooth | BlueBorne — تجاوز مكدس L2CAP | 9.8 |
| CVE-2021-0308 | Cellular | تجاوز محلل SMS في المودم | 8.8 |
| CVE-2022-0847 | Kernel | Dirty Pipe — استبدال page cache | 7.8 |
| CVE-2025-31200 | iOS | CoreAudio AMR decoder overflow | HIGH |
| CVE-2025-31201 | iOS | Kernel PAC bypass | CRITICAL |
| CVE-2025-65885 | Symbian | Delight CFW boot config injection | HIGH |

## الأجهزة المطلوبة

لتشغيل جميع الوحدات، يلزم:
- **وحدة USB**: هاتف أندرويد مع صلاحيات روت ومنفذ DIAG مفعل
- **وحدة iOS**: جهاز آبل A5-A11 في وضع DFU
- **وحدة Wi-Fi**: محول مع دعم وضع المراقبة (RTL8812AU, AR9271)
- **وحدة NFC**: لوحة PN532
- **وحدة EMFI**: ChipSHOUTER (NewAE Technology)
- **وحدة الطاقة**: مقاومة 0.1Ω + بطاقة صوت للـ CPA
- **وحدة LTE**: LimeSDR أو USRP B200 مع srsRAN
- **وحدة FPGA**: Lattice iCE40 أو Xilinx Artix-7

## الترخيص

هذا البرنامج مخصص لاختبار الاختراق المصرح به، واستعادة البيانات الجنائية،
وأغراض البحث التعليمي فقط. استخدامه لأغراض غير مصرح بها قد يكون غير قانوني
في منطقتك القضائية.

## المساهمون

تم تطوير Dragon Legion بواسطة فريق Legion of Dragons الهندسي.

"الفيلق لا يركع لأي مفتاح؛ يختبر كل الأبواب حتى تصبح غير قابلة للكسر."

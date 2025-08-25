@echo off
setlocal ENABLEDELAYEDEXPANSION

REM ==== إعدادات تُعدّلها أنت قبل التشغيل ====
REM ضع رابط الريبو الصحيح هنا (https):
set REPO_URL=https://github.com/abokenan444/veriquantum.git

REM اختياري: اسم وعنوان بريد Git (اكتبهم لو ما كنت مهيئهم سابقًا)
set GIT_NAME=Your Name
set GIT_EMAIL=you@example.com

REM ==== لا تُعدّل تحت هذا السطر عادةً ====
echo.
echo [1/7] الانتقال إلى مجلد السكربت...
cd /d "%~dp0" || ( echo فشل الانتقال للمجلد. & exit /b 1 )

echo [2/7] التحقق من وجود Git...
where git >nul 2>&1 || ( echo لم يتم العثور على Git في PATH. ثبّت Git ثم جرّب مجددًا. & pause & exit /b 1 )

echo [3/7] تهيئة المستودع...
git rev-parse --is-inside-work-tree >nul 2>&1
if errorlevel 1 (
  git init || ( echo فشل git init & pause & exit /b 1 )
) else (
  echo هذا مجلد Git بالفعل — سنكمل.
)

echo [4/7] إعداد اسم وبريد Git (اختياري)...
git config user.name "%GIT_NAME%" >nul 2>&1
git config user.email "%GIT_EMAIL%" >nul 2>&1

echo [5/7] ضبط الفرع الرئيسي main...
git checkout -q -B main

echo [6/7] ربط الريموت origin...
git remote remove origin >nul 2>&1
git remote add origin "%REPO_URL%" || ( echo فشل ربط remote origin & pause & exit /b 1 )

echo [7/7] إضافة ورفع الملفات إلى GitHub...
git add . || ( echo فشل git add & pause & exit /b 1 )
git commit -m "Initial push: VeriQuantum enhanced v2 (WebAuthn, Webhooks, Swagger, Finance, Stripe)" || echo (ملاحظة) لا توجد تغييرات جديدة للالتزام.
git push -u origin main --force || ( echo فشل git push. تأكد من بيانات الدخول أو الصلاحيات. & pause & exit /b 1 )

echo.
echo تم الدفع إلى GitHub بنجاح! افتح الريبو للتحقق.
pause
endlocal
package com.lighty.simspoof;

import android.content.Context;
import android.os.Binder;
import android.os.Parcel;
import android.os.Process;
import android.telephony.SubscriptionInfo;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.Supplier;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class Hook implements IXposedHookLoadPackage {
    private static final String TAG = "SimSpoof: ";

    private static final String CN_ISO = "cn";
    private static final String CN_MCC = "460";

    private static final String SPOOF_ISO = "tw";
    private static final String SPOOF_MCC = "466";
    private static final String SPOOF_MNC = "92";
    private static final String SPOOF_NUMERIC = SPOOF_MCC + SPOOF_MNC;

    private static final String TELEPHONY_PROPS = "android.sysprop.TelephonyProperties";
    private static final String TELEPHONY_MGR = "android.telephony.TelephonyManager";
    private static final String SMS_CLASS = "com.android.internal.telephony.subscription.SubscriptionManagerService";

    private static final Set<String> TARGET_PACKAGES = new HashSet<>(Arrays.asList(
            "com.google.android.gms",
            "com.google.android.gsf",
            "com.google.android.googlequicksearchbox",
            "com.google.android.apps.nexuslauncher",
            "com.google.android.apps.walletnfcrel"
    ));

    private static volatile List<String> realIsoList;
    private static volatile List<String> realNumericList;

    @Override
    public void handleLoadPackage(LoadPackageParam lpp) {
        if (!"com.android.phone".equals(lpp.packageName)) return;
        ClassLoader cl = lpp.classLoader;

        // 1. 写入 sysprop 时仅将中国大陆 SIM (cn / 460*) 伪装为台湾，phone 进程自读时还原真实列表
        hookAll(cl, TELEPHONY_PROPS, "icc_operator_iso_country", createPropHook(
                CN_ISO::equalsIgnoreCase, SPOOF_ISO,
                list -> realIsoList = list, () -> realIsoList
        ));
        hookAll(cl, TELEPHONY_PROPS, "icc_operator_numeric", createPropHook(
                s -> s.startsWith(CN_MCC), SPOOF_NUMERIC,
                list -> realNumericList = list, () -> realNumericList
        ));

        // 2. 绕开 boot-framework 内联，确保 CarrierResolver / CarrierConfigLoader 始终拿到各卡槽真实值
        hookAll(cl, TELEPHONY_MGR, "getSimOperatorNumericForPhone", createPhoneGetterHook(() -> realNumericList));
        hookAll(cl, TELEPHONY_MGR, "getSimCountryIsoForPhone", createPhoneGetterHook(() -> realIsoList));

        // 3. 仅对目标 Google 包返回克隆并伪装后的 SubscriptionInfo，境外卡与其他进程原样放行
        XC_MethodHook subHook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                try {
                    Object res = p.getResult();
                    if (res == null || !isTargetCaller(p.thisObject, p.args)) return;

                    if (res instanceof SubscriptionInfo) {
                        p.setResult(cloneAndSpoof((SubscriptionInfo) res));
                    } else if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> out = new ArrayList<>(list.size());
                        boolean modified = false;
                        for (Object item : list) {
                            if (item instanceof SubscriptionInfo) {
                                SubscriptionInfo orig = (SubscriptionInfo) item;
                                SubscriptionInfo spoofed = cloneAndSpoof(orig);
                                if (spoofed != orig) modified = true;
                                out.add(spoofed);
                            } else {
                                out.add(item);
                            }
                        }
                        if (modified) p.setResult(out);
                    }
                } catch (Throwable t) {
                    log("sub query err: " + t);
                }
            }
        };

        for (String method : new String[] {
                "getActiveSubscriptionInfo",
                "getActiveSubscriptionInfoForSimSlotIndex",
                "getActiveSubscriptionInfoList",
                "getAllSubInfoList",
                "getAvailableSubscriptionInfoList",
                "getAccessibleSubscriptionInfoList"
        }) {
            hookAll(cl, SMS_CLASS, method, subHook);
        }
    }

    private static XC_MethodHook createPropHook(
            Predicate<String> shouldSpoof,
            String spoofValue,
            Consumer<List<String>> saveReal,
            Supplier<List<String>> getReal) {
        return new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                try {
                    if (p.args.length != 1 || !(p.args[0] instanceof List)) return;
                    List<?> raw = (List<?>) p.args[0];
                    List<String> orig = new ArrayList<>(raw.size());
                    List<String> spoofed = new ArrayList<>(raw.size());
                    boolean changed = false;

                    for (Object o : raw) {
                        String s = (o == null) ? null : o.toString();
                        orig.add(s);
                        if (s != null && shouldSpoof.test(s)) {
                            spoofed.add(spoofValue);
                            changed = true;
                        } else {
                            spoofed.add(s);
                        }
                    }

                    saveReal.accept(Collections.unmodifiableList(orig));
                    if (changed) p.args[0] = spoofed;
                } catch (Throwable t) {
                    log("prop write err: " + t);
                }
            }

            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                try {
                    if (p.args.length != 0) return;
                    List<String> orig = getReal.get();
                    if (orig != null) p.setResult(new ArrayList<>(orig));
                } catch (Throwable t) {
                    log("prop read err: " + t);
                }
            }
        };
    }

    private static XC_MethodHook createPhoneGetterHook(Supplier<List<String>> getReal) {
        return new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                try {
                    if (p.args.length < 1 || !(p.args[0] instanceof Integer)) return;
                    int phoneId = (Integer) p.args[0];
                    List<String> orig = getReal.get();
                    if (orig != null && phoneId >= 0 && phoneId < orig.size()) {
                        String real = orig.get(phoneId);
                        String target = (real == null) ? "" : real;
                        if (!target.equals(p.getResult())) p.setResult(target);
                    }
                } catch (Throwable t) {
                    log("phone getter err: " + t);
                }
            }
        };
    }

    private static boolean isTargetCaller(Object service, Object[] args) {
        int uid = Binder.getCallingUid();
        if (uid < Process.FIRST_APPLICATION_UID) return false;

        try {
            Object ctxObj = XposedHelpers.getObjectField(service, "mContext");
            if (ctxObj instanceof Context) {
                long token = Binder.clearCallingIdentity();
                try {
                    String[] pkgs = ((Context) ctxObj).getPackageManager().getPackagesForUid(uid);
                    if (pkgs != null) {
                        for (String pkg : pkgs) {
                            if (TARGET_PACKAGES.contains(pkg)) return true;
                        }
                        return false;
                    }
                } finally {
                    Binder.restoreCallingIdentity(token);
                }
            }
        } catch (Throwable ignored) {
        }

        if (args != null) {
            for (Object arg : args) {
                if (arg instanceof String && TARGET_PACKAGES.contains(arg)) return true;
            }
        }
        return false;
    }

    private static SubscriptionInfo cloneAndSpoof(SubscriptionInfo orig) {
        String iso = orig.getCountryIso();
        String mcc = orig.getMccString();
        if (!CN_ISO.equalsIgnoreCase(iso) && (mcc == null || !mcc.startsWith(CN_MCC))) {
            return orig;
        }

        Parcel parcel = Parcel.obtain();
        SubscriptionInfo copy;
        try {
            orig.writeToParcel(parcel, 0);
            parcel.setDataPosition(0);
            copy = SubscriptionInfo.CREATOR.createFromParcel(parcel);
        } finally {
            parcel.recycle();
        }

        setFieldSafe(copy, "mCountryIso", SPOOF_ISO, 0);
        setFieldSafe(copy, "mMcc", SPOOF_MCC, 466);
        setFieldSafe(copy, "mMnc", SPOOF_MNC, 92);
        return copy;
    }

    private static void setFieldSafe(Object target, String fieldName, String strVal, int intVal) {
        try {
            Field f = XposedHelpers.findFieldIfExists(target.getClass(), fieldName);
            if (f == null) return;
            f.setAccessible(true);
            if (f.getType() == String.class) {
                f.set(target, strVal);
            } else if (f.getType() == int.class || f.getType() == Integer.class) {
                f.set(target, intVal);
            }
        } catch (Throwable t) {
            log("setFieldSafe " + fieldName + " failed: " + t);
        }
    }

    private static void hookAll(ClassLoader cl, String cls, String method, XC_MethodHook h) {
        try {
            Class<?> c = XposedHelpers.findClass(cls, cl);
            if (XposedBridge.hookAllMethods(c, method, h).isEmpty()) {
                log("NO MATCH " + cls + "#" + method);
            }
        } catch (Throwable t) {
            log("FAILED " + cls + "#" + method + ": " + t);
        }
    }

    private static void log(String s) {
        XposedBridge.log(TAG + s);
    }
}
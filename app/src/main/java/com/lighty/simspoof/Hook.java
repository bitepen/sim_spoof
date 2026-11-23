package com.lighty.simspoof;

import android.content.Context;
import android.os.Binder;
import android.os.Parcel;
import android.os.Process;
import android.service.carrier.CarrierIdentifier;
import android.telephony.SubscriptionInfo;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class Hook implements IXposedHookLoadPackage {
    private static final String TAG = "SimSpoof: ";

    // 真实卡信息（中国联通 46001；若日后换其他国内运营商卡，改这里即可）
    private static final String REAL_ISO = "cn";
    private static final String REAL_MCC = "460";
    private static final String REAL_MNC = "01";
    private static final String REAL_NUMERIC = REAL_MCC + REAL_MNC;

    // 伪装给 Google 服务的目标台湾卡信息
    private static final String SPOOF_ISO = "tw";
    private static final String SPOOF_MCC = "466";
    private static final String SPOOF_MNC = "92";
    private static final String SPOOF_NUMERIC = SPOOF_MCC + SPOOF_MNC;

    private static final String PROP_ISO = "gsm.sim.operator.iso-country";
    private static final String PROP_NUMERIC = "gsm.sim.operator.numeric";

    private static final String TELEPHONY_PROPS = "android.sysprop.TelephonyProperties";
    private static final String SYSTEM_PROPS = "android.os.SystemProperties";
    private static final String SMS_CLASS = "com.android.internal.telephony.subscription.SubscriptionManagerService";
    private static final String CCL_CLASS = "com.android.phone.CarrierConfigLoader";
    private static final String CS_WRAPPER = "android.service.carrier.CarrierService$ICarrierServiceWrapper";

    private static final Set<String> TARGET_PACKAGES = new HashSet<>(Arrays.asList(
            "com.google.android.gms",
            "com.google.android.gsf",
            "com.google.android.googlequicksearchbox",
            "com.google.android.apps.nexuslauncher",
            "com.google.android.apps.walletnfcrel"
    ));

    private static volatile List<String> realIsoList = null;
    private static volatile List<String> realNumericList = null;

    @Override
    public void handleLoadPackage(LoadPackageParam lpp) {
        String pkg = lpp.packageName;
        if ("com.android.phone".equals(pkg)) {
            hookPhoneProcess(lpp.classLoader);
        } else {
            // com.google.android.carrier（以及任何你在作用域里额外勾选的运营商/IMS服务）
            // 统一把被全局伪装的 46692 / tw 还原回真实的 46001 / cn
            hookCarrierRestore(lpp.classLoader, pkg);
        }
    }

    private static void hookPhoneProcess(ClassLoader cl) {
        // 1. 写入 sysprop 时伪装，com.android.phone 内部读取时还原
        hookAll(cl, TELEPHONY_PROPS, "icc_operator_iso_country", new XC_MethodHook() {
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
                        if (REAL_ISO.equalsIgnoreCase(s)) {
                            spoofed.add(SPOOF_ISO);
                            changed = true;
                        } else {
                            spoofed.add(s);
                        }
                    }

                    realIsoList = Collections.unmodifiableList(orig);
                    if (changed) {
                        p.args[0] = spoofed;
                        log("write iso-country: " + orig + " -> " + spoofed);
                    }
                } catch (Throwable t) {
                    log("iso-country write err: " + t);
                }
            }

            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                try {
                    if (p.args.length != 0) return;
                    List<String> orig = realIsoList;
                    if (orig != null) {
                        p.setResult(new ArrayList<>(orig));
                    } else if (p.getResult() instanceof List) {
                        List<String> fixed = restoreList((List<?>) p.getResult(), SPOOF_ISO, REAL_ISO);
                        if (fixed != null) p.setResult(fixed);
                    }
                } catch (Throwable t) {
                    log("iso-country read err: " + t);
                }
            }
        });

        hookAll(cl, TELEPHONY_PROPS, "icc_operator_numeric", new XC_MethodHook() {
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
                        if (s != null && s.startsWith(REAL_MCC)) {
                            spoofed.add(SPOOF_NUMERIC);
                            changed = true;
                        } else {
                            spoofed.add(s);
                        }
                    }

                    realNumericList = Collections.unmodifiableList(orig);
                    if (changed) {
                        p.args[0] = spoofed;
                        log("write numeric: " + orig + " -> " + spoofed);
                    }
                } catch (Throwable t) {
                    log("numeric write err: " + t);
                }
            }

            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                try {
                    if (p.args.length != 0) return;
                    List<String> orig = realNumericList;
                    if (orig != null) {
                        p.setResult(new ArrayList<>(orig));
                    } else if (p.getResult() instanceof List) {
                        List<String> fixed = restoreList((List<?>) p.getResult(), SPOOF_NUMERIC, REAL_NUMERIC);
                        if (fixed != null) p.setResult(fixed);
                    }
                } catch (Throwable t) {
                    log("numeric read err: " + t);
                }
            }
        });

        // 2. 兜底拦截 com.android.phone 内部通过 SystemProperties.get 直接读属性的路径
        hookSystemPropertiesRestore(cl, "com.android.phone");

        // 3. 兜底检查 CarrierConfigLoader 构造出的 CarrierIdentifier
        hookAll(cl, CCL_CLASS, "getCarrierIdentifierForPhoneId", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                try {
                    Object res = p.getResult();
                    if (res instanceof CarrierIdentifier) {
                        CarrierIdentifier id = (CarrierIdentifier) res;
                        if (fixCarrierIdentifier(id)) {
                            log("phone fixed CarrierIdentifier -> " + id);
                        } else {
                            log("phone CarrierIdentifier ok: mcc=" + id.getMcc() + " mnc=" + id.getMnc());
                        }
                    }
                } catch (Throwable t) {
                    log("CCL hook err: " + t);
                }
            }
        });

        // 4. 仅对 Google 目标包伪装 SubscriptionInfo 副本
        XC_MethodHook subHook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                try {
                    Object res = p.getResult();
                    if (res == null) return;
                    if (!isTargetCaller(p.thisObject, p.args)) return;

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
                        if (modified) {
                            p.setResult(out);
                        }
                    }
                } catch (Throwable t) {
                    log("sub query err: " + t);
                }
            }
        };

        String[] subMethods = new String[] {
                "getActiveSubscriptionInfo",
                "getActiveSubscriptionInfoForSimSlotIndex",
                "getActiveSubscriptionInfoList",
                "getAllSubInfoList",
                "getAvailableSubscriptionInfoList",
                "getAccessibleSubscriptionInfoList"
        };
        for (String m : subMethods) {
            hookAll(cl, SMS_CLASS, m, subHook);
        }
    }

    private static void hookCarrierRestore(ClassLoader cl, String pkg) {
        log("init restore hook in " + pkg);

        hookAll(cl, TELEPHONY_PROPS, "icc_operator_numeric", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                if (p.args.length != 0 || !(p.getResult() instanceof List)) return;
                List<String> fixed = restoreList((List<?>) p.getResult(), SPOOF_NUMERIC, REAL_NUMERIC);
                if (fixed != null) {
                    p.setResult(fixed);
                    log(pkg + " restored icc_operator_numeric -> " + fixed);
                }
            }
        });

        hookAll(cl, TELEPHONY_PROPS, "icc_operator_iso_country", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                if (p.args.length != 0 || !(p.getResult() instanceof List)) return;
                List<String> fixed = restoreList((List<?>) p.getResult(), SPOOF_ISO, REAL_ISO);
                if (fixed != null) {
                    p.setResult(fixed);
                }
            }
        });

        hookSystemPropertiesRestore(cl, pkg);

        hookAll(cl, CS_WRAPPER, "getCarrierConfig", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                if (p.args == null) return;
                for (Object arg : p.args) {
                    if (arg instanceof CarrierIdentifier) {
                        CarrierIdentifier id = (CarrierIdentifier) arg;
                        if (fixCarrierIdentifier(id)) {
                            log(pkg + " fixed incoming CarrierIdentifier -> " + id);
                        } else {
                            log(pkg + " incoming CarrierIdentifier: mcc=" + id.getMcc() + " mnc=" + id.getMnc());
                        }
                    }
                }
            }
        });
    }

    private static void hookSystemPropertiesRestore(ClassLoader cl, String pkg) {
        hookAll(cl, SYSTEM_PROPS, "get", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                if (p.args.length < 1 || !(p.args[0] instanceof String)) return;
                String key = (String) p.args[0];
                boolean isNumeric = PROP_NUMERIC.equals(key);
                boolean isIso = !isNumeric && PROP_ISO.equals(key);
                if (!isNumeric && !isIso) return;

                Object res = p.getResult();
                if (!(res instanceof String)) return;
                String val = (String) res;
                String fixed = isNumeric
                        ? restorePropString(val, SPOOF_NUMERIC, REAL_NUMERIC)
                        : restorePropString(val, SPOOF_ISO, REAL_ISO);
                if (fixed != null) {
                    p.setResult(fixed);
                }
            }
        });
    }

    private static boolean fixCarrierIdentifier(CarrierIdentifier id) {
        if (SPOOF_MCC.equals(id.getMcc()) && SPOOF_MNC.equals(id.getMnc())) {
            setFieldSafe(id, "mMcc", REAL_MCC, 460);
            setFieldSafe(id, "mMnc", REAL_MNC, 1);
            return true;
        }
        return false;
    }

    private static List<String> restoreList(List<?> list, String spoofed, String real) {
        List<String> out = new ArrayList<>(list.size());
        boolean changed = false;
        for (Object o : list) {
            String s = (o == null) ? null : o.toString();
            if (spoofed.equalsIgnoreCase(s)) {
                out.add(real);
                changed = true;
            } else {
                out.add(s);
            }
        }
        return changed ? out : null;
    }

    private static String restorePropString(String val, String spoofed, String real) {
        if (val == null || val.isEmpty()) return null;
        String[] parts = val.split(",", -1);
        boolean changed = false;
        for (int i = 0; i < parts.length; i++) {
            if (spoofed.equalsIgnoreCase(parts[i].trim())) {
                parts[i] = real;
                changed = true;
            }
        }
        if (!changed) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(parts[i]);
        }
        return sb.toString();
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
                if (arg instanceof String && TARGET_PACKAGES.contains(arg)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static SubscriptionInfo cloneAndSpoof(SubscriptionInfo orig) {
        String iso = orig.getCountryIso();
        String mcc = orig.getMccString();
        boolean isCn = REAL_ISO.equalsIgnoreCase(iso) || (mcc != null && mcc.startsWith(REAL_MCC));
        if (!isCn) return orig;

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
            int n = XposedBridge.hookAllMethods(c, method, h).size();
            log("hooked " + cls + "#" + method + " x" + n);
        } catch (Throwable t) {
            log("FAILED " + cls + "#" + method + ": " + t);
        }
    }

    private static void log(String s) {
        XposedBridge.log(TAG + s);
    }
}
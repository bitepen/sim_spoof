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

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class Hook implements IXposedHookLoadPackage {
    private static final String TAG = "SimSpoof: ";

    private static final String ISO_FROM = "cn";
    private static final String ISO_TO = "tw";
    private static final String MCC_FROM = "460";
    private static final String MCC_TO = "466";
    private static final String MNC_TO = "92";
    private static final String NUMERIC_TO = MCC_TO + MNC_TO;

    private static final String TELEPHONY_PROPS = "android.sysprop.TelephonyProperties";
    private static final String SMS_CLASS = "com.android.internal.telephony.subscription.SubscriptionManagerService";

    // 仅对这些 Google 包伪装 SubscriptionInfo，避免误伤 Carrier Services / Pixel IMS 等组件
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
        if (!"com.android.phone".equals(lpp.packageName)) return;
        ClassLoader cl = lpp.classLoader;

        // 1. 拦截 gsm.sim.operator.iso-country：写入时伪装为 tw，com.android.phone 自己读取时还给它真实值
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
                        if (ISO_FROM.equalsIgnoreCase(s)) {
                            spoofed.add(ISO_TO);
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
                    }
                } catch (Throwable t) {
                    log("iso-country read err: " + t);
                }
            }
        });

        // 2. 拦截 gsm.sim.operator.numeric：写入时伪装为 46692，com.android.phone 内部读取时返回真实 460xx 保住联通配置
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
                        if (s != null && s.startsWith(MCC_FROM)) {
                            spoofed.add(NUMERIC_TO);
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
                    }
                } catch (Throwable t) {
                    log("numeric read err: " + t);
                }
            }
        });

        // 3. 拦截 SubscriptionManagerService 对外查询接口，按调用方包名定向返回克隆并伪装后的 SubscriptionInfo
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

        // 兜底：若未来版本字段名变化，检查方法入参中的 callingPackage
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
        boolean isCn = ISO_FROM.equalsIgnoreCase(iso) || (mcc != null && mcc.startsWith(MCC_FROM));
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

        setFieldSafe(copy, "mCountryIso", ISO_TO, 0);
        setFieldSafe(copy, "mMcc", MCC_TO, 466);
        setFieldSafe(copy, "mMnc", MNC_TO, 92);
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
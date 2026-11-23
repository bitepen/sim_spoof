package com.lighty.simspoof;

import android.content.Context;
import android.os.Binder;
import android.os.Parcel;
import android.os.Process;
import android.service.carrier.CarrierIdentifier;
import android.telephony.SubscriptionInfo;
import android.telephony.SubscriptionManager;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class Hook implements IXposedHookLoadPackage {
    private static final String TAG = "SimSpoof: ";

    // 仅针对中国大陆 SIM (cn / 460*) 伪装为台湾 (tw / 46692)，境外卡完全放行不碰
    private static final String CN_ISO = "cn";
    private static final String CN_MCC = "460";

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

    // 仅对这些 Google 用户态包伪装 SubscriptionInfo
    private static final Set<String> TARGET_PACKAGES = new HashSet<>(Arrays.asList(
            "com.google.android.gms",
            "com.google.android.gsf",
            "com.google.android.googlequicksearchbox",
            "com.google.android.apps.nexuslauncher",
            "com.google.android.apps.walletnfcrel"
    ));

    private static volatile List<String> realIsoList = null;
    private static volatile List<String> realNumericList = null;
    private static final ThreadLocal<Boolean> IN_LOOKUP = new ThreadLocal<>();

    @Override
    public void handleLoadPackage(LoadPackageParam lpp) {
        String pkg = lpp.packageName;
        if ("com.android.phone".equals(pkg)) {
            hookPhoneProcess(lpp.classLoader);
        } else {
            hookCarrierRestore(lpp.classLoader, pkg);
        }
    }

    private static void hookPhoneProcess(ClassLoader cl) {
        // 1. 写入 sysprop 时仅伪装 cn / 460*，并记录各卡槽原始真实值；phone 进程自读时动态还原
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
                        if (CN_ISO.equalsIgnoreCase(s)) {
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
                        if (s != null && s.startsWith(CN_MCC)) {
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
                    }
                } catch (Throwable t) {
                    log("numeric read err: " + t);
                }
            }
        });

        // 2. 兜底拦截 com.android.phone 内部通过 SystemProperties.get 的直接读取（按内存真实列表还原，无硬编码）
        hookAll(cl, SYSTEM_PROPS, "get", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                if (p.args.length < 1 || !(p.args[0] instanceof String)) return;
                String key = (String) p.args[0];
                if (PROP_NUMERIC.equals(key)) {
                    List<String> orig = realNumericList;
                    if (orig != null && !orig.isEmpty()) {
                        p.setResult(joinList(orig));
                    }
                } else if (PROP_ISO.equals(key)) {
                    List<String> orig = realIsoList;
                    if (orig != null && !orig.isEmpty()) {
                        p.setResult(joinList(orig));
                    }
                }
            }
        });

        // 3. 核查并按真实卡槽动态修正 CarrierConfigLoader 构造出的 CarrierIdentifier
        hookAll(cl, CCL_CLASS, "getCarrierIdentifierForPhoneId", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                try {
                    Object res = p.getResult();
                    if (!(res instanceof CarrierIdentifier)) return;
                    CarrierIdentifier id = (CarrierIdentifier) res;
                    int phoneId = (p.args.length >= 1 && p.args[0] instanceof Integer) ? (Integer) p.args[0] : -1;

                    List<String> orig = realNumericList;
                    if (phoneId >= 0 && orig != null && phoneId < orig.size()) {
                        String realNum = orig.get(phoneId);
                        if (realNum != null && realNum.startsWith(CN_MCC) && realNum.length() >= 5
                                && SPOOF_MCC.equals(id.getMcc()) && SPOOF_MNC.equals(id.getMnc())) {
                            setFieldSafe(id, "mMcc", realNum.substring(0, 3), parseIntSafe(realNum.substring(0, 3), 460));
                            setFieldSafe(id, "mMnc", realNum.substring(3), parseIntSafe(realNum.substring(3), 0));
                            log("phone fixed CarrierIdentifier[slot=" + phoneId + "] -> mcc="
                                    + id.getMcc() + " mnc=" + id.getMnc()
                                    + " cid=" + id.getCarrierId() + " scid=" + id.getSpecificCarrierId());
                            return;
                        }
                    }

                    log("phone CarrierIdentifier[slot=" + phoneId + "]: mcc="
                            + id.getMcc() + " mnc=" + id.getMnc()
                            + " cid=" + id.getCarrierId() + " scid=" + id.getSpecificCarrierId());
                } catch (Throwable t) {
                    log("CCL hook err: " + t);
                }
            }
        });

        // 4. 仅对目标 Google 包伪装中国大陆卡的 SubscriptionInfo 副本，境外卡原样放行
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
        log("init dynamic restore hook in " + pkg);

        hookAll(cl, TELEPHONY_PROPS, "icc_operator_numeric", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                if (p.args.length != 0 || !(p.getResult() instanceof List)) return;
                List<String> fixed = restoreListByRealSlots((List<?>) p.getResult(), true);
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
                List<String> fixed = restoreListByRealSlots((List<?>) p.getResult(), false);
                if (fixed != null) {
                    p.setResult(fixed);
                }
            }
        });

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
                String fixed = restorePropStringByRealSlots((String) res, isNumeric);
                if (fixed != null) {
                    p.setResult(fixed);
                }
            }
        });

        hookAll(cl, CS_WRAPPER, "getCarrierConfig", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                if (p.args == null) return;
                for (Object arg : p.args) {
                    if (arg instanceof CarrierIdentifier) {
                        CarrierIdentifier id = (CarrierIdentifier) arg;
                        if (fixCarrierIdentifierDynamic(id)) {
                            log(pkg + " fixed incoming CarrierIdentifier -> mcc="
                                    + id.getMcc() + " mnc=" + id.getMnc()
                                    + " cid=" + id.getCarrierId() + " scid=" + id.getSpecificCarrierId());
                        } else {
                            log(pkg + " incoming CarrierIdentifier: mcc="
                                    + id.getMcc() + " mnc=" + id.getMnc()
                                    + " cid=" + id.getCarrierId() + " scid=" + id.getSpecificCarrierId());
                        }
                    }
                }
            }
        });
    }

    // 动态向 SubscriptionManager 查询真实的 CN 卡槽信息（不会触发硬编码，也不误伤真实台湾/境外卡）
    private static List<SubscriptionInfo> getRealCnSubInfos() {
        if (Boolean.TRUE.equals(IN_LOOKUP.get())) return Collections.emptyList();
        IN_LOOKUP.set(Boolean.TRUE);
        try {
            Class<?> at = XposedHelpers.findClass("android.app.ActivityThread", null);
            Object appObj = XposedHelpers.callStaticMethod(at, "currentApplication");
            if (!(appObj instanceof Context)) return Collections.emptyList();

            SubscriptionManager sm = ((Context) appObj).getSystemService(SubscriptionManager.class);
            if (sm == null) return Collections.emptyList();

            List<SubscriptionInfo> active = sm.getActiveSubscriptionInfoList();
            if (active == null || active.isEmpty()) return Collections.emptyList();

            List<SubscriptionInfo> cnSubs = new ArrayList<>();
            for (SubscriptionInfo info : active) {
                String mcc = info.getMccString();
                String iso = info.getCountryIso();
                if ((mcc != null && mcc.startsWith(CN_MCC)) || CN_ISO.equalsIgnoreCase(iso)) {
                    cnSubs.add(info);
                }
            }
            return cnSubs;
        } catch (Throwable ignored) {
            return Collections.emptyList();
        } finally {
            IN_LOOKUP.remove();
        }
    }

    private static Map<Integer, String> buildRealCnSlotMap(boolean numeric) {
        List<SubscriptionInfo> cnSubs = getRealCnSubInfos();
        if (cnSubs.isEmpty()) return Collections.emptyMap();

        Map<Integer, String> map = new HashMap<>();
        for (SubscriptionInfo info : cnSubs) {
            int slot = info.getSimSlotIndex();
            if (slot < 0) continue;
            if (numeric) {
                String mcc = info.getMccString();
                String mnc = info.getMncString();
                if (mcc != null && mnc != null && !mcc.isEmpty() && !mnc.isEmpty()) {
                    map.put(slot, mcc + mnc);
                }
            } else {
                String iso = info.getCountryIso();
                map.put(slot, (iso != null && !iso.isEmpty()) ? iso : CN_ISO);
            }
        }
        return map;
    }

    private static List<String> restoreListByRealSlots(List<?> list, boolean numeric) {
        Map<Integer, String> slotMap = buildRealCnSlotMap(numeric);
        if (slotMap.isEmpty()) return null;

        String spoofToken = numeric ? SPOOF_NUMERIC : SPOOF_ISO;
        List<String> out = new ArrayList<>(list.size());
        boolean changed = false;

        for (int i = 0; i < list.size(); i++) {
            Object o = list.get(i);
            String s = (o == null) ? null : o.toString();
            if (slotMap.containsKey(i) && spoofToken.equalsIgnoreCase(s)) {
                out.add(slotMap.get(i));
                changed = true;
            } else {
                out.add(s);
            }
        }
        return changed ? out : null;
    }

    private static String restorePropStringByRealSlots(String val, boolean numeric) {
        if (val == null || val.isEmpty()) return null;
        String spoofToken = numeric ? SPOOF_NUMERIC : SPOOF_ISO;
        if (!val.toLowerCase().contains(spoofToken)) return null;

        Map<Integer, String> slotMap = buildRealCnSlotMap(numeric);
        if (slotMap.isEmpty()) return null;

        String[] parts = val.split(",", -1);
        boolean changed = false;
        for (int i = 0; i < parts.length; i++) {
            if (slotMap.containsKey(i) && spoofToken.equalsIgnoreCase(parts[i].trim())) {
                parts[i] = slotMap.get(i);
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

    private static boolean fixCarrierIdentifierDynamic(CarrierIdentifier id) {
        if (!SPOOF_MCC.equals(id.getMcc()) || !SPOOF_MNC.equals(id.getMnc())) return false;
        List<SubscriptionInfo> cnSubs = getRealCnSubInfos();
        if (cnSubs.isEmpty()) return false;

        SubscriptionInfo matched = null;
        for (SubscriptionInfo info : cnSubs) {
            if (info.getCarrierId() == id.getCarrierId()) {
                matched = info;
                break;
            }
        }
        if (matched == null && cnSubs.size() == 1) {
            matched = cnSubs.get(0);
        }
        if (matched == null) return false;

        String realMcc = matched.getMccString();
        String realMnc = matched.getMncString();
        if (realMcc == null || realMnc == null || realMcc.isEmpty() || realMnc.isEmpty()) return false;

        setFieldSafe(id, "mMcc", realMcc, parseIntSafe(realMcc, 460));
        setFieldSafe(id, "mMnc", realMnc, parseIntSafe(realMnc, 0));
        return true;
    }

    private static String joinList(List<String> list) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(',');
            String s = list.get(i);
            if (s != null) sb.append(s);
        }
        return sb.toString();
    }

    private static int parseIntSafe(String s, int fallback) {
        try {
            return Integer.parseInt(s);
        } catch (Throwable ignored) {
            return fallback;
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
        boolean isCn = CN_ISO.equalsIgnoreCase(iso) || (mcc != null && mcc.startsWith(CN_MCC));
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
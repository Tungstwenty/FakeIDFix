package tungstwenty.xposed.fakeidfix;

import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;

import java.lang.reflect.Method;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

import android.app.AndroidAppHelper;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class XposedMod implements IXposedHookZygoteInit, IXposedHookLoadPackage {

	private static final String THIS_PACKAGE = XposedMod.class.getPackage().getName();
	private static final String BLUEBOX_PACKAGE = "com.bluebox.labs.onerootscanner";

	private static boolean romAlreadyFixed = false;
	private static boolean hooksInstalled = false;

	private static final ThreadLocal<Object> insideCollectCertificates = new ThreadLocal<Object>();

	@Override
	public void initZygote(StartupParam startupParam) throws Throwable {

		try {
			// Check for the presence of the fixed method signature
			XposedHelpers.findMethodExact("org.apache.harmony.security.utils.JarUtils", null, "createChain",
			    X509Certificate.class, X509Certificate[].class, boolean.class);
			// No need to install the hooks, ROM already includes the fix
			romAlreadyFixed = true;
			return;

		} catch (Throwable t) {
		}

		findAndHookMethod("org.apache.harmony.security.utils.JarUtils", null, "createChain", X509Certificate.class,
		    X509Certificate[].class, new XC_MethodHook() {
			    @Override
			    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
				    if (insideCollectCertificates.get() == null) {
					    // Not in a relevant place, default to previous behavior
					    return;
				    }

				    try {
					    X509Certificate signer = (X509Certificate) param.args[0];
					    X509Certificate[] candidates = (X509Certificate[]) param.args[1];
					    param.setResult(createChain_fix(signer, candidates));
				    } catch (Throwable t) {
					    // If any exception occurs, send it to the caller as the invocation result
					    // instead of having Xposed fallback to the original (unpatched) method
					    param.setThrowable(t);
				    }
			    }
		    });

		findAndHookMethod("android.content.pm.PackageParser", null, "collectCertificates",
		    "android.content.pm.PackageParser$Package", int.class, new XC_MethodHook() {
			    @Override
			    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
				    // Only apply the fixed method for system services
				    if ("android".equals(AndroidAppHelper.currentPackageName())) {
					    insideCollectCertificates.set("dummy");
				    }
			    }

			    @Override
			    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
				    insideCollectCertificates.set(null);
			    }
		    });

		// No errors occurred while installing the hooks
		hooksInstalled = true;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private static X509Certificate[] createChain_fix(X509Certificate signer, X509Certificate[] candidates) {
		LinkedList chain = new LinkedList();
		chain.add(0, signer);
		// Signer is self-signed
		if (signer.getSubjectDN().equals(signer.getIssuerDN())) {
			return (X509Certificate[]) chain.toArray(new X509Certificate[1]);
		}
		Principal issuer = signer.getIssuerDN();
		X509Certificate issuerCert;
		X509Certificate subjectCert = signer;
		int count = 1;
		while (true) {
			issuerCert = findCert_fix(issuer, candidates, subjectCert, true);
			if (issuerCert == null) {
				break;
			}
			chain.add(issuerCert);
			count++;
			if (issuerCert.getSubjectDN().equals(issuerCert.getIssuerDN())) {
				break;
			}
			issuer = issuerCert.getIssuerDN();
			subjectCert = issuerCert;
		}
		return (X509Certificate[]) chain.toArray(new X509Certificate[count]);
	}

	private static X509Certificate findCert_fix(Principal issuer, X509Certificate[] candidates,
	                                            X509Certificate subjectCert, boolean chainCheck) {
		for (int i = 0; i < candidates.length; i++) {
			if (issuer.equals(candidates[i].getSubjectDN())) {
				if (chainCheck) {
					try {
						subjectCert.verify(candidates[i].getPublicKey());
					} catch (Exception e) {
						continue;
					}
				}
				return candidates[i];
			}
		}
		return null;
	}

	@Override
	public void handleLoadPackage(LoadPackageParam lpparam) throws Throwable {
		// Report "green" status if the module installed the hooks successfully OR if it wasn't needed
		if (THIS_PACKAGE.equals(lpparam.packageName) && (hooksInstalled || romAlreadyFixed)) {
			findAndHookMethod(XposedModActivity.class.getName(), lpparam.classLoader, "isActive",
			    XC_MethodReplacement.returnConstant(true));
		}

		// Affect Bluebox Security Scanner detection only if the module is active and the ROM wasn't already fixed
		if (BLUEBOX_PACKAGE.equals(lpparam.packageName) && !romAlreadyFixed && hooksInstalled) {
			// Change the reported "createChain" method signature to include the 3rd parameter on the official AOSP correction
			findAndHookMethod(Method.class, "getParameterTypes", new XC_MethodHook() {
				@Override
				protected void afterHookedMethod(MethodHookParam param) throws Throwable {
					Method m = (Method) param.thisObject;
					if ("createChain".equals(m.getName())
					        && "org.apache.harmony.security.utils.JarUtils".equals(m.getDeclaringClass().getName())) {
						Class<?>[] result = (Class<?>[]) param.getResult();
						if (result.length == 2) {
							// Simulate that the method receives a 3rd parameter, boolean
							Class<?>[] newResult = new Class<?>[3];
							System.arraycopy(result, 0, newResult, 0, 2);
							newResult[2] = boolean.class;
							param.setResult(newResult);
						}
					}
				}
			});
		}
	}

}


#include <config.h>
#include <glib.h>

#include <jni.h>

#include <errno.h>

#if defined(HOST_DARWIN)
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <mach/machine.h>
#elif defined(LINUX)
#include <sys/types.h>
#include <sys/stat.h>
#elif defined(HOST_WIN32)
#include <windows.h>
#endif

#ifdef HOST_ANDROID
#include <sys/system_properties.h>
#else
#define PROP_NAME_MAX   32
#define PROP_VALUE_MAX  92
#endif

#include "android.h"
#include "threads.h"
#include "appdomain.h"

#include "utils/mono-logger-internals.h"
#include "utils/mono-dl.h"

#if defined(HOST_ANDROID) && defined(ANDROID64)
#define SYSTEM_LIB_PATH "/system/lib64"
#elif defined(HOST_ANDROID)
#define SYSTEM_LIB_PATH "/system/lib"
// #elif LINUX_FLATPAK
// #define SYSTEM_LIB_PATH "/app/lib/mono"
#elif LINUX
#define SYSTEM_LIB_PATH "/usr/lib"
#elif HOST_DARWIN
#define SYSTEM_LIB_PATH "/Library/Frameworks/Xamarin.Android.framework/Libraries/"
#elif HOST_WIN32
#define SYSTEM_LIB_PATH get_xamarin_android_msbuild_path()
#else
#define SYSTEM_LIB_PATH ""
#endif

/* Symbols which are accessed via `DllImport("__Internal")` or `dlsym` */

MONO_API void
mono_jvm_initialize (JavaVM *vm);

JNIEnv*
mono_jvm_get_jnienv (void);

MONO_API void
monodroid_add_system_property (const gchar *name, const gchar *value);

MONO_API gint32
monodroid_get_system_property (const gchar *name, gchar **value);

MONO_API void
monodroid_free (gpointer ptr);

MONO_API gint32
_monodroid_max_gref_get (void);

MONO_API gint32
_monodroid_gref_get (void);

MONO_API void
_monodroid_gref_log (const gchar *message);

MONO_API void
_monodroid_weak_gref_new (jobject curHandle, gchar curType, jobject newHandle, gchar newType, const gchar *threadName, gint32 threadId, gchar *from, gint32 from_writable);

MONO_API void
_monodroid_weak_gref_delete (jobject handle, gchar type, const gchar *threadName, gint32 threadId, gchar *from, gint32 from_writable);

MONO_API void
_monodroid_lref_log_new (gint32 lrefc, jobject handle, gchar type, const gchar *threadName, gint32 threadId, gchar *from, gint32 from_writable);

MONO_API void
_monodroid_lref_log_delete (gint32 lrefc, jobject handle, gchar type, const gchar *threadName, gint32 threadId, gchar *from, gint32 from_writable);

MONO_API const gchar *
monodroid_typemap_java_to_managed (const gchar *java);

MONO_API const gchar *
monodroid_typemap_managed_to_java (const gchar *managed);

MONO_API gpointer
_monodroid_get_identity_hash_code (JNIEnv *env, gpointer v);

MONO_API void
_monodroid_gc_wait_for_bridge_processing (void);

MONO_API gint32
_monodroid_gref_log_new (jobject curHandle, gchar curType, jobject newHandle, gchar newType, const gchar *threadName, gint32 threadId, gchar *from, gint32 from_writable);

MONO_API void
_monodroid_gref_log_delete (jobject handle, gchar type, const gchar *threadName, gint32 threadId, gchar *from, gint32 from_writable);

JNIEXPORT void JNICALL
Java_mono_android_Runtime_init (JNIEnv *env, jclass klass, jstring lang, jobjectArray runtimeApks, jstring runtimeNativeLibDir, jobjectArray appDirs, jobject loader, jobjectArray externalStorageDirs, jobjectArray assemblies, jstring packageName);

JNIEXPORT void JNICALL
Java_mono_android_Runtime_register (JNIEnv *, jclass, jstring, jclass, jstring);

JNIEXPORT void JNICALL
Java_mono_android_Runtime_notifyTimeZoneChanged (JNIEnv *, jclass);

JNIEXPORT jint JNICALL
Java_mono_android_Runtime_createNewContext (JNIEnv *, jclass, jobjectArray, jobjectArray, jobject);

JNIEXPORT void JNICALL
Java_mono_android_Runtime_switchToContext (JNIEnv *, jclass, jint);

JNIEXPORT void JNICALL
Java_mono_android_Runtime_destroyContexts (JNIEnv *, jclass, jintArray);

JNIEXPORT void JNICALL
Java_mono_android_Runtime_propagateUncaughtException (JNIEnv *, jclass, jobject, jthrowable);

/* Functions from `libmonodroid` that we are dynamically loading */

static struct {
	gboolean loaded;
	MonoDl *dlhandle;

	gint32 (*_monodroid_max_gref_get) (void);
	gint32 (*_monodroid_gref_get) (void);
	void (*_monodroid_gref_log) (const gchar *message);
	void (*_monodroid_weak_gref_new) (jobject curHandle, gchar curType, jobject newHandle, gchar newType, const gchar *threadName, gint32 threadId, gchar *from, gint32 from_writable);
	void (*_monodroid_weak_gref_delete) (jobject handle, gchar type, const gchar *threadName, gint32 threadId, gchar *from, gint32 from_writable);
	void (*_monodroid_lref_log_new) (gint32 lrefc, jobject handle, gchar type, const gchar *threadName, gint32 threadId, gchar *from, gint32 from_writable);
	void (*_monodroid_lref_log_delete) (gint32 lrefc, jobject handle, gchar type, const gchar *threadName, gint32 threadId, gchar *from, gint32 from_writable);
	const gchar* (*monodroid_typemap_java_to_managed) (const gchar *java);
	const gchar* (*monodroid_typemap_managed_to_java) (const gchar *managed);
	gpointer (*_monodroid_get_identity_hash_code) (JNIEnv *env, gpointer v);
	void (*_monodroid_gc_wait_for_bridge_processing) (void);
	gint32 (*_monodroid_gref_log_new) (jobject curHandle, gchar curType, jobject newHandle, gchar newType, const gchar *threadName, gint32 threadId, gchar *from, gint32 from_writable);
	void (*_monodroid_gref_log_delete) (jobject handle, gchar type, const gchar *threadName, gint32 threadId, gchar *from, gint32 from_writable);

	void (*monodroid_runtime_init) (JNIEnv*, jclass, jstring, jobjectArray, jstring, jobjectArray, jobject, jobjectArray, jobjectArray, jstring);
	void (*monodroid_runtime_register) (JNIEnv*, jclass, jstring, jclass, jstring);
	void (*monodroid_runtime_notifyTimeZoneChanged) (JNIEnv*, jclass);
	jint (*monodroid_runtime_createNewContext) (JNIEnv*, jclass, jobjectArray, jobjectArray, jobject);
	void (*monodroid_runtime_switchToContext) (JNIEnv*, jclass, jint);
	void (*monodroid_runtime_destroyContexts) (JNIEnv*, jclass, jintArray);
	void (*monodroid_runtime_propagateUncaughtException) (JNIEnv*, jclass, jobject, jthrowable);
} monodroid;

static gboolean initialized = FALSE;

static JavaVM *jvm;

static jclass     TimeZone_class;
static jmethodID  TimeZone_getDefault;
static jmethodID  TimeZone_getID;

static jclass     NetworkInterface_class;
static jmethodID  NetworkInterface_getByName;
static jmethodID  NetworkInterface_isUp;
static jmethodID  NetworkInterface_supportsMulticast;

static jobject
lref_to_gref (JNIEnv *env, jobject lref)
{
	jobject g;
	if (lref == 0)
		return 0;
	g = (*env)->NewGlobalRef (env, lref);
	(*env)->DeleteLocalRef (env, lref);
	return g;
}

void
mono_jvm_initialize (JavaVM *vm)
{
	JNIEnv *env;

	if (initialized)
		return;

	jvm = vm;

	(*jvm)->GetEnv (jvm, (gpointer*)&env, JNI_VERSION_1_6);

	TimeZone_class = lref_to_gref (env, (*env)->FindClass (env, "java/util/TimeZone"));
	if (!TimeZone_class)
		g_error ("%s: Fatal error: Could not find java.util.TimeZone class!", __func__);

	TimeZone_getDefault = (*env)->GetStaticMethodID (env, TimeZone_class, "getDefault", "()Ljava/util/TimeZone;");
	if (!TimeZone_getDefault)
		g_error ("%s: Fatal error: Could not find java.util.TimeZone.getDefault() method!", __func__);

	TimeZone_getID = (*env)->GetMethodID (env, TimeZone_class, "getID", "()Ljava/lang/String;");
	if (!TimeZone_getID)
		g_error ("%s: Fatal error: Could not find java.util.TimeZone.getDefault() method!", __func__);

	NetworkInterface_class = lref_to_gref (env, (*env)->FindClass (env, "java/net/NetworkInterface"));
	if (!NetworkInterface_class)
		g_error ("Fatal error: Could not find java.net.NetworkInterface class!");

	NetworkInterface_getByName = (*env)->GetStaticMethodID (env, NetworkInterface_class, "getByName", "(Ljava/lang/String;)Ljava/net/NetworkInterface;");
	if (!NetworkInterface_getByName)
		g_error ("Fatal error: Could not find java.net.NetworkInterface.getByName() method!");

	NetworkInterface_isUp = (*env)->GetMethodID (env, NetworkInterface_class, "isUp", "()Z");
	if (!NetworkInterface_isUp)
		g_error ("Fatal error: Could not find java.net.NetworkInterface.isUp() method!");

	NetworkInterface_supportsMulticast = (*env)->GetMethodID (env, NetworkInterface_class, "supportsMulticast", "()Z");
	if (!NetworkInterface_supportsMulticast)
		g_error ("Fatal error: Could not find java.net.NetworkInterface.supportsMulticast() method!");

	initialized = TRUE;
}

JNIEXPORT jint JNICALL
JNI_OnLoad (JavaVM *vm, gpointer reserved)
{
	mono_jvm_initialize (vm);
	return JNI_VERSION_1_6;
}

JNIEnv*
mono_jvm_get_jnienv (void)
{
	JNIEnv *env;

	g_assert (initialized);

	(*jvm)->GetEnv (jvm, (void**)&env, JNI_VERSION_1_6);
	if (env)
		return env;

	(*jvm)->AttachCurrentThread(jvm, &env, NULL);
	if (env)
		return env;

	g_error ("%s: Fatal error: Could not create env", __func__);
}

struct BundledProperty {
	gchar *name;
	gchar *value;
	gint   value_len;
	struct BundledProperty *next;
};

static struct BundledProperty* bundled_properties;

static struct BundledProperty*
lookup_system_property (const gchar *name)
{
	struct BundledProperty *p = bundled_properties;
	for ( ; p ; p = p->next)
		if (strcmp (p->name, name) == 0)
			return p;
	return NULL;
}

void
monodroid_add_system_property (const gchar *name, const gchar *value)
{
	gint name_len, value_len;

	struct BundledProperty* p = lookup_system_property (name);
	if (p) {
		gchar *n = g_strdup (value);
		g_free (p->value);
		p->value      = n;
		p->value_len  = strlen (p->value);
		return;
	}

	name_len  = strlen (name);
	value_len = strlen (value);

	p = g_malloc0 (sizeof (struct BundledProperty) + name_len + 1);

	p->name = ((char*) p) + sizeof (struct BundledProperty);
	strncpy (p->name, name, name_len);
	p->name [name_len] = '\0';

	p->value      = g_strdup (value);
	p->value_len  = value_len;

	p->next             = bundled_properties;
	bundled_properties  = p;
}

#if defined(HOST_ANDROID) && defined(ANDROID64)
/* __system_property_get was removed in Android 5.0/64bit
   this is hopefully temporary replacement, until we find better
   solution

   sp_value buffer should be at least PROP_VALUE_MAX+1 bytes long
*/
static gint
_monodroid__system_property_get (const gchar *name, gchar *sp_value, gsize sp_value_len)
{
	if (!name)
		return -1;

	g_assert (sp_value);
	g_assert (sp_value_len == PROP_VALUE_MAX + 1);

	gchar *cmd = g_strdup_printf ("getprop %s", name);
	FILE* result = popen (cmd, "r");
	gint len = (gint) fread (sp_value, 1, sp_value_len, result);
	fclose (result);
	sp_value [len] = 0;
	if (len > 0 && sp_value [len - 1] == '\n') {
		sp_value [len - 1] = 0;
		len--;
	} else {
		if (len != 0)
			len = 0;
		sp_value [0] = 0;
	}

	mono_trace (G_LOG_LEVEL_MESSAGE, MONO_TRACE_ANDROID_DEFAULT, "%s %s: '%s' len: %d", __func__, name, sp_value, len);

	return len;
}
#elif defined(HOST_ANDROID)
static gint
_monodroid__system_property_get (const gchar *name, gchar *sp_value, gsize sp_value_len)
{
	if (!name)
		return -1;

	g_assert (sp_value);
	g_assert (sp_value_len == PROP_VALUE_MAX + 1);

	return __system_property_get (name, sp_value);
}
#else
static void
monodroid_strreplace (gchar *buffer, gchar old_char, gchar new_char)
{
	if (buffer == NULL)
		return;
	while (*buffer != '\0') {
		if (*buffer == old_char)
			*buffer = new_char;
		buffer++;
	}
}

static gint
_monodroid__system_property_get (const gchar *name, gchar *sp_value, gsize sp_value_len)
{
	if (!name)
		return -1;

	g_assert (sp_value);
	g_assert (sp_value_len == PROP_VALUE_MAX + 1);

	gchar *env_name = g_strdup_printf ("__XA_%s", name);
	monodroid_strreplace (env_name, '.', '_');
	gchar *env_value = g_getenv (env_name);
	g_free (env_name);

	gsize env_value_len = env_value ? strlen (env_value) : 0;
	if (env_value_len == 0) {
		sp_value[0] = '\0';
		return 0;
	}

	if (env_value_len >= sp_value_len)
		mono_trace (G_LOG_LEVEL_WARNING, MONO_TRACE_ANDROID_DEFAULT, "System property buffer size too small by %u bytes", env_value_len == sp_value_len ? 1 : env_value_len - sp_value_len);

	strncpy (sp_value, env_value, sp_value_len);
	sp_value[sp_value_len] = '\0';

	return strlen (sp_value);
}
#endif

gint32
monodroid_get_system_property (const gchar *name, gchar **value)
{
	gchar  buf [PROP_VALUE_MAX+1] = { 0, };
	gint   len;
	struct BundledProperty *p;

	g_assert (value);
	*value = NULL;

	len = _monodroid__system_property_get (name, buf, sizeof (buf));
	if (len > 0) {
		*value = g_strndup (buf, len);
		return len;
	}

	if ((p = lookup_system_property (name))) {
		*value = g_strndup (p->value, p->value_len);
		return p->value_len;
	}

	return -1;
}

void
monodroid_free (gpointer ptr)
{
	g_free (ptr);
}

gint32
ves_icall_System_TimezoneInfo_AndroidTimeZones_GetSystemProperty (const gchar *name, gchar **value)
{
	return monodroid_get_system_property (name, value);
}

gpointer
ves_icall_System_TimezoneInfo_AndroidTimeZones_GetDefaultTimeZoneId (void)
{
	JNIEnv *env = mono_jvm_get_jnienv ();
	jobject d = (*env)->CallStaticObjectMethod (env, TimeZone_class, TimeZone_getDefault);
	jstring id = (*env)->CallObjectMethod (env, d, TimeZone_getID);
	const gchar *mutf8 = (*env)->GetStringUTFChars (env, id, NULL);

	gchar *def_id = g_strdup (mutf8);

	(*env)->ReleaseStringUTFChars (env, id, mutf8);
	(*env)->DeleteLocalRef (env, id);
	(*env)->DeleteLocalRef (env, d);

	return def_id;
}

#if HOST_ANDROID && __arm__

#define BUF_SIZE 512

static gboolean
find_in_maps (const gchar *str)
{
	FILE  *maps;
	gchar *line;
	gchar  buf [BUF_SIZE];

	g_assert (str);

	maps = fopen ("/proc/self/maps", "r");
	if (!maps)
		return FALSE;

	while ((line = fgets (buf, BUF_SIZE, maps))) {
		if (strstr (line, str)) {
			fclose (maps);
			return TRUE;
		}
	}

	fclose (maps);
	return FALSE;
}

static gboolean
detect_houdini ()
{
	return find_in_maps ("libhoudini");
}

#endif // HOST_ANDROID && __arm__

static gboolean
is_64_bit (void)
{
	return SIZEOF_VOID_P == 8;
}

#define CPU_KIND_UNKNOWN ((guint16)0)
#define CPU_KIND_ARM     ((guint16)1)
#define CPU_KIND_ARM64   ((guint16)2)
#define CPU_KIND_MIPS    ((guint16)3)
#define CPU_KIND_X86     ((guint16)4)
#define CPU_KIND_X86_64  ((guint16)5)

static guint16
get_built_for_cpu (void)
{
#if HOST_WIN32
# if _M_AMD64 || _M_X64
	return CPU_KIND_X86_64;
# elif _M_IX86
	return CPU_KIND_X86;
# elif _M_ARM
	return CPU_KIND_ARM;
# else
	return CPU_KIND_UNKNOWN;
# endif
#elif HOST_DARWIN
# if __x86_64__
	return CPU_KIND_X86_64;
# elif __i386__
	return CPU_KIND_X86;
# else
	return CPU_KIND_UNKNOWN;
# endif
#else
# if __arm__
	return CPU_KIND_ARM;
# elif __aarch64__
	return CPU_KIND_ARM64;
# elif __x86_64__
	return CPU_KIND_X86_64;
# elif __i386__
	return CPU_KIND_X86;
# elif __mips__
	return CPU_KIND_MIPS;
# else
	return CPU_KIND_UNKNOWN;
# endif
#endif // HOST_WIN32
}

static guint16
get_running_on_cpu (void)
{
#ifdef HOST_WIN32
	SYSTEM_INFO si;

	GetSystemInfo (&si);
	switch (si.wProcessorArchitecture) {
		case PROCESSOR_ARCHITECTURE_AMD64:
			return CPU_KIND_X86_64;
		case PROCESSOR_ARCHITECTURE_ARM:
			return CPU_KIND_ARM;
		case PROCESSOR_ARCHITECTURE_INTEL:
			return CPU_KIND_X86;
		default:
			return CPU_KIND_UNKNOWN;
	}
#elif HOST_DARWIN
	cpu_type_t cputype;
	size_t length;

	length = sizeof (cputype);
	sysctlbyname ("hw.cputype", &cputype, &length, NULL, 0);
	switch (cputype) {
		case CPU_TYPE_X86:
			return CPU_KIND_X86;
		case CPU_TYPE_X86_64:
			return CPU_KIND_X86_64;
		default:
			return CPU_KIND_UNKNOWN;
	}
#else
# if __arm__
	if (!detect_houdini ()) {
		return CPU_KIND_ARM;
	} else {
		/* If houdini is mapped in we're running on x86 */
		return CPU_KIND_X86;
	}
# elif __aarch64__
	return CPU_KIND_ARM64;
# elif __x86_64__
	return CPU_KIND_X86_64;
# elif __i386__
	return is_64_bit () ? CPU_KIND_X86_64 : CPU_KIND_X86;
# elif __mips__
	return CPU_KIND_MIPS;
# else
	return CPU_KIND_UNKNOWN;
# endif
#endif // HOST_WIN32
}

void
ves_icall_Mono_Unix_Android_AndroidUtils_DetectCpuAndArchitecture (guint16 *built_for_cpu, guint16 *running_on_cpu, MonoBoolean *is64bit)
{
	g_assert (is64bit);
	*is64bit = (guint8) is_64_bit ();
	g_assert (built_for_cpu);
	*built_for_cpu = get_built_for_cpu ();
	g_assert (running_on_cpu);
	*running_on_cpu = get_running_on_cpu ();
}

gint32
ves_icall_System_Net_NetworkInformation_UnixIPInterfaceProperties_GetDNSServers (gpointer *dns_servers_array)
{
	g_assert (dns_servers_array);
	*dns_servers_array = NULL;

	gsize  len;
	gchar *dns;
	gchar *dns_servers [8];
	gint   count = 0;
	gchar  prop_name[] = "net.dnsX";
	for (gint i = 0; i < 8; i++) {
		prop_name [7] = (char)(i + 0x31);
		len = monodroid_get_system_property (prop_name, &dns);
		if (len <= 0) {
			dns_servers [i] = NULL;
			continue;
		}
		dns_servers [i] = g_strndup (dns, len);
		count++;
	}

	if (count <= 0)
		return 0;

	gchar **ret = g_new (gchar*, count);
	gchar **p = ret;
	for (gint i = 0; i < 8; i++) {
		if (!dns_servers [i])
			continue;
		*p++ = dns_servers [i];
	}

	*dns_servers_array = (gpointer)ret;
	return count;
}

static MonoBoolean
_monodroid_get_network_interface_state (const gchar *ifname, MonoBoolean *is_up, MonoBoolean *supports_multicast)
{
	if (!ifname || strlen (ifname) == 0 || (!is_up && !supports_multicast))
		return FALSE;

	g_assert (NetworkInterface_class);
	g_assert (NetworkInterface_getByName);

	JNIEnv *env = mono_jvm_get_jnienv ();
	jstring NetworkInterface_nameArg = (*env)->NewStringUTF (env, ifname);
	jobject networkInterface = (*env)->CallStaticObjectMethod (env, NetworkInterface_class, NetworkInterface_getByName, NetworkInterface_nameArg);
	(*env)->DeleteLocalRef (env, NetworkInterface_nameArg);

	if (!networkInterface) {
		mono_trace (G_LOG_LEVEL_WARNING, MONO_TRACE_ANDROID_NET, "Failed to look up interface '%s' using Java API", ifname);
		return FALSE;
	}

	if (is_up) {
		g_assert (NetworkInterface_isUp);
		*is_up = (gboolean)(*env)->CallBooleanMethod (env, networkInterface, NetworkInterface_isUp);
	}

	if (supports_multicast) {
		g_assert (NetworkInterface_supportsMulticast);
		*supports_multicast = (gboolean)(*env)->CallBooleanMethod (env, networkInterface, NetworkInterface_supportsMulticast);
	}

	return TRUE;
}

MonoBoolean
ves_icall_System_Net_NetworkInformation_LinuxNetworkInterface_GetUpState (const gchar *ifname, MonoBoolean *is_up)
{
	return _monodroid_get_network_interface_state (ifname, is_up, NULL);
}

MonoBoolean
ves_icall_System_Net_NetworkInformation_LinuxNetworkInterface_GetSupportsMulticast (const gchar *ifname, MonoBoolean *supports_multicast)
{
	return _monodroid_get_network_interface_state (ifname, NULL, supports_multicast);
}

#ifdef HOST_WIN32
static const gchar*
monodroid_get_directory_path (void)
{
	static char *libmonoandroid_directory_path = NULL;
	wchar_t module_path[MAX_PATH];
	HMODULE module = NULL;

	if (libmonoandroid_directory_path)
		return libmonoandroid_directory_path;

	DWORD flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
	if (!GetModuleHandleExW (flags, (void*)&libmonoandroid_directory_path, &module))
		return NULL;

	GetModuleFileNameW (module, module_path, sizeof (module_path) / sizeof (module_path[0]));
	PathRemoveFileSpecW (module_path);
	libmonoandroid_directory_path = utf16_to_utf8 (module_path);
	return libmonoandroid_directory_path;
}
#endif

static void
monodroid_copy_file_content (const gchar *from_filename, const gchar *to_filename)
{
	FILE *from_file = NULL, *to_file = NULL;
	gchar buf[4096];
	gsize n;

	from_file = g_fopen (from_filename, "r");
	if (!from_file) {
		mono_trace (G_LOG_LEVEL_WARNING, MONO_TRACE_ANDROID_DEFAULT, "%s: failed to open \"%s\", error: (%d) \"%s\"", __func__, from_filename, errno, g_strerror (errno));
		goto exit;
	}

	to_file = g_fopen (to_filename, "wx");
	if (!to_file) {
		mono_trace (G_LOG_LEVEL_WARNING, MONO_TRACE_ANDROID_DEFAULT, "%s: failed to open \"%s\", error: (%d) \"%s\"", __func__, to_filename, errno, g_strerror (errno));
		goto exit;
	}

	while ((n = fread (buf, sizeof(char), sizeof(buf), from_file)) > 0) {
		if (fwrite (buf, sizeof(char), n, to_file) != n) {
			mono_trace (G_LOG_LEVEL_WARNING, MONO_TRACE_ANDROID_DEFAULT, "%s: failed to copy \"%s\" to \"%s\", error: (%d) \"%s\"", __func__, from_filename, to_filename, errno, g_strerror(errno));
			goto exit;
		}
	}

exit:
	if (from_file)
		fclose (from_file);
	if (to_file)
		fclose (to_file);
}

static void
monodroid_copy_file (const gchar *from, const gchar *to, const gchar *filename)
{
	gchar *from_filename, *to_filename;
	
	from_filename = g_build_filename (from, filename);
	g_assert (from_filename);

	if (!g_file_test (from_filename, G_FILE_TEST_EXISTS)) {
		mono_trace (G_LOG_LEVEL_WARNING, MONO_TRACE_ANDROID_DEFAULT, "%s: failed to copy \"%s\" from \"%s\", file doesn't exist", __func__, filename, from);
		g_free (from_filename);
		return;
	}

	mono_trace (G_LOG_LEVEL_WARNING, MONO_TRACE_ANDROID_DEFAULT, "%s: copying \"%s\" from \"%s\" to \"%s\"", __func__, filename, from, to);

	to_filename = g_build_filename (to, filename);
	g_assert (to_filename);

	g_unlink (to_filename);

	monodroid_copy_file_content (from_filename, to_filename);

	g_free (from_filename);
	g_free (to_filename);
}

static const gchar*
monodroid_get_path (JNIEnv *env, jstring primary_override_dir_j, jstring external_override_dir_j, jstring external_legacy_override_dir_j, jstring app_libdir_j, jstring runtime_libdir_j)
{
	char *primary_override_dir, *external_override_dir, *external_legacy_override_dir, *app_libdir, *runtime_libdir;
	const char *temp;

	temp = (*env)->GetStringUTFChars (env, primary_override_dir_j, NULL);
	primary_override_dir = g_build_filename (temp, ".__override__");
	(*env)->ReleaseStringUTFChars (env, primary_override_dir_j, temp);

	temp = (*env)->GetStringUTFChars (env, external_override_dir_j, NULL);
	external_override_dir = g_strdup (temp);
	(*env)->ReleaseStringUTFChars (env, external_override_dir_j, temp);

	temp = (*env)->GetStringUTFChars (env, external_legacy_override_dir_j, NULL);
	external_legacy_override_dir = g_strdup (temp);
	(*env)->ReleaseStringUTFChars (env, external_legacy_override_dir_j, temp);

	temp = (*env)->GetStringUTFChars (env, app_libdir_j, NULL);
	app_libdir = g_strdup (temp);
	(*env)->ReleaseStringUTFChars (env, app_libdir_j, temp);

	temp = (*env)->GetStringUTFChars (env, runtime_libdir_j, NULL);
	runtime_libdir = g_strdup (temp);
	(*env)->ReleaseStringUTFChars (env, runtime_libdir_j, temp);

#if defined(HOST_ANDROID) || defined(LINUX)
#define LIBMONODROID "libmonodroid.so"
#elif defined(HOST_DARWIN)
#define LIBMONODROID "libmonodroid.dylib"
#elif defined(HOST_WIN32)
#define LIBMONODROID "libmonodroid.dll"
#else
#error "missing definition of LIBMONODROID"
#endif

#define TRY_LOAD_LIBMONODROID(dir) \
	do { \
		if (dir) { \
			const gchar *libmonodroid = g_build_filename (dir, LIBMONODROID); \
			mono_trace (G_LOG_LEVEL_WARNING, MONO_TRACE_ANDROID_DEFAULT, "%s: trying to load libmonodroid from \"%s\"", __func__, libmonodroid); \
			if (g_file_test (libmonodroid, G_FILE_TEST_EXISTS)) \
				return libmonodroid; \
			g_free (libmonodroid); \
		} \
	} while (0)

#ifndef RELEASE
	TRY_LOAD_LIBMONODROID (primary_override_dir);

	// Android 5 includes some restrictions on loading dynamic libraries via dlopen() from
	// external storage locations so we need to file copy the shared object to an internal
	// storage location before loading it.

	monodroid_copy_file (external_override_dir, primary_override_dir, LIBMONODROID);
	TRY_LOAD_LIBMONODROID (primary_override_dir);

	monodroid_copy_file (external_legacy_override_dir, primary_override_dir, LIBMONODROID);
	TRY_LOAD_LIBMONODROID (primary_override_dir);
#endif

	TRY_LOAD_LIBMONODROID (app_libdir);

	if (runtime_libdir) {
		/* Copy libmonodroid to "`primary_override_dir`/links" */
		const gchar *libmonodroid = g_build_filename(runtime_libdir, LIBMONODROID);
		if (g_file_test (libmonodroid, G_FILE_TEST_EXISTS)) {
			const gchar *links_dir = g_build_filename (primary_override_dir, "links");
			if (!g_file_test (primary_override_dir, G_FILE_TEST_EXISTS))
				g_mkdir (primary_override_dir, 0777);
			if (!g_file_test (links_dir, G_FILE_TEST_EXISTS))
				g_mkdir (links_dir, 0777);

			const gchar *libmonodroid_link = g_build_filename (links_dir, LIBMONODROID);
			if (!g_file_test (libmonodroid_link, G_FILE_TEST_EXISTS))
				monodroid_copy_file (libmonodroid, links_dir, LIBMONODROID);

			g_free (libmonodroid);
			libmonodroid = libmonodroid_link;

			g_free (links_dir);
		}
		mono_trace (G_LOG_LEVEL_WARNING, MONO_TRACE_ANDROID_DEFAULT, "%s: trying to load libmonodroid from \"%s\"", __func__, libmonodroid);
		if (g_file_test (libmonodroid, G_FILE_TEST_EXISTS))
			return libmonodroid;
		g_free (libmonodroid);
	}

#ifdef HOST_WIN32
	TRY_LOAD_LIBMONODROID (monodroid_get_directory_path ());
#endif

	TRY_LOAD_LIBMONODROID (SYSTEM_LIB_PATH);

#undef TRY_LOAD_LIBMONODROID
#undef LIBMONODROID

	g_error ("%s: failed to load libmonodroid.", __func__);
}

static void
monodroid_load (const gchar *libmonodroid_path)
{
	g_assert (!monodroid.loaded);

	g_assert (libmonodroid_path);

	char *error_msg;
	monodroid.dlhandle = mono_dl_open (libmonodroid_path, MONO_DL_LAZY, &error_msg);
	if (!monodroid.dlhandle) {
		mono_trace (G_LOG_LEVEL_WARNING, MONO_TRACE_ANDROID_DEFAULT, "%s: failed to load libmonodroid, err: \"%s\"", __func__, error_msg);
		g_free (error_msg);
		return;
	}

#define LOAD_SYMBOL(symbol) \
	do { \
		error_msg = mono_dl_symbol (monodroid.dlhandle, #symbol, &monodroid.symbol); \
		g_assertf(monodroid.symbol, "%s: failed to load libmonodroid symbol \"%s\", err: \"%s\"", __func__, #symbol, error_msg); \
	} while (0)

	LOAD_SYMBOL (_monodroid_gc_wait_for_bridge_processing);
	LOAD_SYMBOL (_monodroid_get_identity_hash_code);
	LOAD_SYMBOL (_monodroid_gref_get);
	LOAD_SYMBOL (_monodroid_gref_log_delete);
	LOAD_SYMBOL (_monodroid_gref_log_new);
	LOAD_SYMBOL (_monodroid_gref_log);
	LOAD_SYMBOL (_monodroid_lref_log_delete);
	LOAD_SYMBOL (_monodroid_lref_log_new);
	LOAD_SYMBOL (_monodroid_max_gref_get);
	LOAD_SYMBOL (_monodroid_weak_gref_delete);
	LOAD_SYMBOL (_monodroid_weak_gref_new);
	LOAD_SYMBOL (monodroid_typemap_java_to_managed);
	LOAD_SYMBOL (monodroid_typemap_managed_to_java);

	LOAD_SYMBOL (monodroid_runtime_init);
	LOAD_SYMBOL (monodroid_runtime_register);
	LOAD_SYMBOL (monodroid_runtime_notifyTimeZoneChanged);
	LOAD_SYMBOL (monodroid_runtime_createNewContext);
	LOAD_SYMBOL (monodroid_runtime_switchToContext);
	LOAD_SYMBOL (monodroid_runtime_destroyContexts);
	LOAD_SYMBOL (monodroid_runtime_propagateUncaughtException);

#undef LOAD_SYMBOL

	monodroid.loaded = TRUE;
}

gint32
_monodroid_max_gref_get (void)
{
	return monodroid._monodroid_max_gref_get ();
}

gint32
_monodroid_gref_get (void)
{
	return monodroid._monodroid_gref_get ();
}

void
_monodroid_gref_log (const gchar *message)
{
	monodroid._monodroid_gref_log (message);
}

void
_monodroid_weak_gref_new (jobject curHandle, gchar curType, jobject newHandle, gchar newType, const gchar *threadName, gint32 threadId, gchar *from, gint32 from_writable)
{
	monodroid._monodroid_weak_gref_new (curHandle, curType, newHandle, newType, threadName, threadId, from, from_writable);
}

void
_monodroid_weak_gref_delete (jobject handle, gchar type, const gchar *threadName, gint32 threadId, gchar *from, gint32 from_writable)
{
	monodroid._monodroid_weak_gref_delete (handle, type, threadName, threadId, from, from_writable);
}

void
_monodroid_lref_log_new (gint32 lrefc, jobject handle, gchar type, const gchar *threadName, gint32 threadId, gchar *from, gint32 from_writable)
{
	monodroid._monodroid_lref_log_new (lrefc, handle, type, threadName, threadId, from, from_writable);
}

void
_monodroid_lref_log_delete (gint32 lrefc, jobject handle, gchar type, const gchar *threadName, gint32 threadId, gchar *from, gint32 from_writable)
{
	monodroid._monodroid_lref_log_delete (lrefc, handle, type, threadName, threadId, from, from_writable);
}

const gchar *
monodroid_typemap_java_to_managed (const gchar *java)
{
	return monodroid.monodroid_typemap_java_to_managed (java);
}

const gchar *
monodroid_typemap_managed_to_java (const gchar *managed)
{
	return monodroid.monodroid_typemap_managed_to_java (managed);
}

gpointer
_monodroid_get_identity_hash_code (JNIEnv *env, gpointer v)
{
	return monodroid._monodroid_get_identity_hash_code (env, v);
}

void
_monodroid_gc_wait_for_bridge_processing (void)
{
	monodroid._monodroid_gc_wait_for_bridge_processing ();
}

gint32
_monodroid_gref_log_new (jobject curHandle, gchar curType, jobject newHandle, gchar newType, const gchar *threadName, gint32 threadId, gchar *from, gint32 from_writable)
{
	return monodroid._monodroid_gref_log_new (curHandle, curType, newHandle, newType, threadName, threadId, from, from_writable);
}

void
_monodroid_gref_log_delete (jobject handle, gchar type, const gchar *threadName, gint32 threadId, gchar *from, gint32 from_writable)
{
	monodroid._monodroid_gref_log_delete (handle, type, threadName, threadId, from, from_writable);
}

JNIEXPORT void JNICALL
Java_mono_android_Runtime_init (JNIEnv *env, jclass klass, jstring lang, jobjectArray runtimeApks, jstring runtimeNativeLibDir, jobjectArray appDirs, jobject loader, jobjectArray externalStorageDirs, jobjectArray assemblies, jstring packageName)
{
	monodroid_load (
		monodroid_get_path (
			env,
			(*env)->GetObjectArrayElement (env, appDirs, 0),
			(*env)->GetObjectArrayElement (env, externalStorageDirs, 0),
			(*env)->GetObjectArrayElement (env, externalStorageDirs, 1),
			(*env)->GetObjectArrayElement (env, appDirs, 2),
			runtimeNativeLibDir));

	monodroid.monodroid_runtime_init (env, klass, lang, runtimeApks, runtimeNativeLibDir, appDirs, loader, externalStorageDirs, assemblies, packageName);
}

JNIEXPORT void JNICALL
Java_mono_android_Runtime_register (JNIEnv *env, jclass klass, jstring managedType, jclass nativeClass, jstring methods)
{
	monodroid.monodroid_runtime_register(env, klass, managedType, nativeClass, methods);
}

JNIEXPORT void JNICALL
Java_mono_android_Runtime_notifyTimeZoneChanged (JNIEnv *env, jclass klass)
{
	monodroid.monodroid_runtime_notifyTimeZoneChanged (env, klass);
}

JNIEXPORT jint JNICALL
Java_mono_android_Runtime_createNewContext (JNIEnv *env, jclass klass, jobjectArray runtimeApks, jobjectArray assemblies, jobject loader)
{
	monodroid.monodroid_runtime_createNewContext (env, klass, runtimeApks, assemblies, loader);
}

JNIEXPORT void JNICALL
Java_mono_android_Runtime_switchToContext (JNIEnv *env, jclass klass, jint contextID)
{
	monodroid.monodroid_runtime_switchToContext (env, klass, contextID);
}

JNIEXPORT void JNICALL
Java_mono_android_Runtime_destroyContexts (JNIEnv *env, jclass klass, jintArray array)
{
	monodroid.monodroid_runtime_destroyContexts (env, klass, array);
}

JNIEXPORT void JNICALL
Java_mono_android_Runtime_propagateUncaughtException (JNIEnv *env, jclass klass, jobject javaThread, jthrowable javaException)
{
	monodroid.monodroid_runtime_propagateUncaughtException (env, klass, javaThread, javaException);
}

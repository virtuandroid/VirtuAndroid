package mirror.android.app;


import mirror.RefClass;
import mirror.RefStaticMethod;

public class ActivityTaskManager {
    public static Class<?> TYPE = RefClass.load(ActivityTaskManager.class, "android.app.ActivityTaskManager");
    public static RefStaticMethod<Object> getInstance;
    public static RefStaticMethod<Object> getService;
}

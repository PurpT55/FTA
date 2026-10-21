"""droidtriage – offline analysis of DroidCollector / adb_collect.sh Android evidence.

Library use::

    from droidtriage.evidence import Evidence
    from droidtriage.iocs import IocDb
    from droidtriage.model import Context, Options
    from droidtriage.pipeline import run_all
    from droidtriage.report import write_all

    ctx = run_all(Context(Evidence("dump.zip"), IocDb(), Options(trusted_installers={"com.android.vending"})))
    write_all(ctx, "out/")
"""
__version__ = "1.1.0"

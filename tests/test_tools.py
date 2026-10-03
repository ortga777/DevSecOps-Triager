from src.tools import analyze_build_failure, scan_secrets

def test_secret_scan():
    assert scan_secrets("token = 'ghp_abcdefghijklmnopqrstuvwxyz123456'")

def test_build_analysis():
    result = analyze_build_failure('ok\nERROR: test failed\n')
    assert result['error_count'] == 1

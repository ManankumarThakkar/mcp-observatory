def test_package_exposes_version():
    import analyzer

    assert analyzer.__version__ == "0.1.0"

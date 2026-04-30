"""
Test suite for PhishGuard AI detection algorithm
Tests high/medium/low risk classification and individual pattern detection
"""

import pytest
from detect import analyze_message


# ==============================================================================
# HIGH RISK TEST CASES (Score >= 60)
# ==============================================================================

def test_high_risk_multiple_patterns():
    """Test message with multiple high-risk indicators"""
    message = "URGENT: Your Amazon account has been SUSPENDED. Click here to verify: https://bit.ly/verify123"
    result = analyze_message(message)
    
    assert result['classification'] == "HIGH RISK"
    assert result['risk_score'] >= 60
    assert result['color'] == "red"
    assert len(result['patterns_detected']) >= 3


def test_high_risk_phishing_with_personal_info():
    """Test phishing attempt requesting sensitive information"""
    message = "Security alert! Verify your SSN and credit card immediately: http://secure-bank.tk"
    result = analyze_message(message)
    
    assert result['classification'] == "HIGH RISK"
    assert result['risk_score'] >= 60
    assert any("sensitive personal information" in p.lower() for p in result['patterns_detected'])
    assert any("suspicious" in p.lower() for p in result['patterns_detected'])


def test_high_risk_financial_scam():
    """Test prize/lottery scam message"""
    message = "Congratulations! You WON $5000. Claim your prize NOW: https://tinyurl.com/winner123"
    result = analyze_message(message)
    
    assert result['classification'] == "HIGH RISK"
    assert result['risk_score'] >= 60
    assert any("financial incentive" in p.lower() for p in result['patterns_detected'])


def test_high_risk_account_threat():
    """Test message with account threat language"""
    message = "URGENT: Your account has been compromised. Unauthorized activity detected. Click here immediately."
    result = analyze_message(message)
    
    assert result['classification'] == "HIGH RISK"
    assert result['risk_score'] >= 60
    assert any("account threat" in p.lower() for p in result['patterns_detected'])


# ==============================================================================
# MEDIUM RISK TEST CASES (Score 30-59)
# ==============================================================================

def test_medium_risk_urgency_only():
    """Test message with urgency but no other major threats"""
    message = "Please verify your account within 24 hours. Action required."
    result = analyze_message(message)
    
    assert result['classification'] == "MEDIUM RISK"
    assert 30 <= result['risk_score'] < 60
    assert result['color'] == "orange"


def test_medium_risk_generic_greeting_with_url():
    """Test generic greeting with URL"""
    message = "Dear Customer, your package delivery failed. Click to reschedule: http://delivery-update.com"
    result = analyze_message(message)
    
    assert result['classification'] == "MEDIUM RISK"
    assert 30 <= result['risk_score'] < 60


def test_medium_risk_brand_impersonation():
    """Test possible brand impersonation"""
    message = "Your Netflix subscription payment failed. Update your payment method."
    result = analyze_message(message)
    
    assert result['classification'] == "MEDIUM RISK"
    assert any("brand impersonation" in p.lower() for p in result['patterns_detected'])


# ==============================================================================
# LOW RISK TEST CASES (Score < 30)
# ==============================================================================

def test_low_risk_normal_message():
    """Test normal, legitimate message"""
    message = "Hi John, meeting is scheduled for tomorrow at 2pm in conference room B."
    result = analyze_message(message)
    
    assert result['classification'] == "LOW RISK"
    assert result['risk_score'] < 30
    assert result['color'] == "green"


def test_low_risk_legitimate_notification():
    """Test legitimate order confirmation"""
    message = "Your order #12345 has shipped. Track your package at amazon.com/orders"
    result = analyze_message(message)
    
    assert result['classification'] == "LOW RISK"
    assert result['risk_score'] < 30


def test_low_risk_friendly_message():
    """Test friendly, personal message"""
    message = "Hey! How are you doing? Want to grab coffee this weekend?"
    result = analyze_message(message)
    
    assert result['classification'] == "LOW RISK"
    assert result['risk_score'] < 30
    assert len(result['patterns_detected']) == 0


# ==============================================================================
# INDIVIDUAL PATTERN DETECTION TESTS
# ==============================================================================

def test_url_detection():
    """Test that URLs are detected"""
    message = "Check this out: https://example.com"
    result = analyze_message(message)
    
    assert any("URL" in p for p in result['patterns_detected'])


def test_suspicious_domain_detection():
    """Test detection of suspicious domains"""
    test_cases = [
        "Click here: http://site.tk",
        "Visit: https://bit.ly/abc123",
        "Link: http://tinyurl.com/xyz",
        "Check: http://domain.ml"
    ]
    
    for message in test_cases:
        result = analyze_message(message)
        assert any("suspicious" in p.lower() and "domain" in p.lower() 
                  for p in result['patterns_detected'])


def test_urgency_keyword_detection():
    """Test urgency keyword detection"""
    urgency_messages = [
        "URGENT: Action required",
        "Act now before it's too late",
        "Immediate verification needed",
        "Account suspended - click here"
    ]
    
    for message in urgency_messages:
        result = analyze_message(message)
        assert any("urgency" in p.lower() for p in result['patterns_detected'])


def test_generic_greeting_detection():
    """Test generic greeting detection"""
    greetings = [
        "Dear Customer, we need your attention",
        "Dear User, please verify",
        "Dear Valued Member, urgent notice"
    ]
    
    for message in greetings:
        result = analyze_message(message)
        assert any("generic" in p.lower() or "impersonal" in p.lower() 
                  for p in result['patterns_detected'])


def test_financial_bait_detection():
    """Test financial incentive detection"""
    financial_messages = [
        "You won $1000!",
        "Claim your prize now",
        "Free gift card available",
        "Cash reward waiting"
    ]
    
    for message in financial_messages:
        result = analyze_message(message)
        assert any("financial incentive" in p.lower() for p in result['patterns_detected'])


def test_personal_info_request_detection():
    """Test detection of personal information requests"""
    info_requests = [
        "Please confirm your SSN",
        "Verify your credit card number",
        "Enter your password to continue",
        "Update your bank account information"
    ]
    
    for message in info_requests:
        result = analyze_message(message)
        assert any("personal information" in p.lower() for p in result['patterns_detected'])


def test_excessive_caps_detection():
    """Test excessive capitalization detection"""
    message = "URGENT NOTICE YOUR ACCOUNT HAS BEEN SUSPENDED"
    result = analyze_message(message)
    
    assert any("capitalization" in p.lower() for p in result['patterns_detected'])


def test_brand_impersonation_detection():
    """Test brand impersonation detection"""
    brands = ["Amazon", "PayPal", "Apple", "Microsoft", "Google", "Netflix"]
    
    for brand in brands:
        message = f"Your {brand} account needs verification"
        result = analyze_message(message)
        assert any("brand" in p.lower() for p in result['patterns_detected'])


# ==============================================================================
# EDGE CASES AND BOUNDARY TESTS
# ==============================================================================

def test_empty_message():
    """Test handling of empty message"""
    result = analyze_message("")
    
    assert result['classification'] == "LOW RISK"
    assert result['risk_score'] == 0
    assert len(result['patterns_detected']) == 0


def test_score_capped_at_100():
    """Test that score never exceeds 100"""
    # Create message with EVERY possible pattern
    message = """
    URGENT URGENT URGENT! Dear Customer,
    Your Amazon account has been SUSPENDED and COMPROMISED.
    You WON $10000 PRIZE. Click https://bit.ly/scam123
    Verify your SSN, password, and credit card IMMEDIATELY.
    Unauthorized activity detected. Account will be TERMINATED.
    """
    result = analyze_message(message)
    
    assert result['risk_score'] <= 100
    assert result['risk_score'] == 100  # Should be maxed out


def test_whitespace_only():
    """Test message with only whitespace"""
    result = analyze_message("   \n\t   ")
    
    assert result['classification'] == "LOW RISK"
    assert result['risk_score'] == 0


def test_special_characters():
    """Test message with special characters"""
    message = "!@#$%^&*()_+-=[]{}|;:',.<>?/"
    result = analyze_message(message)
    
    assert result['classification'] == "LOW RISK"


def test_mixed_case_url():
    """Test URL detection with mixed case"""
    message = "Check this: HTTP://BIT.LY/ABC123"
    result = analyze_message(message)
    
    assert any("URL" in p for p in result['patterns_detected'])


# ==============================================================================
# RESPONSE FORMAT VALIDATION TESTS
# ==============================================================================

def test_response_structure():
    """Test that response has all required fields"""
    message = "Test message"
    result = analyze_message(message)
    
    assert 'risk_score' in result
    assert 'classification' in result
    assert 'recommendation' in result
    assert 'patterns_detected' in result
    assert 'color' in result


def test_risk_score_is_integer():
    """Test that risk score is an integer"""
    message = "Test message"
    result = analyze_message(message)
    
    assert isinstance(result['risk_score'], int)


def test_classification_values():
    """Test that classification is one of the expected values"""
    messages = [
        "Normal message",
        "Dear Customer, please verify",
        "URGENT: Click here https://bit.ly/scam verify your SSN NOW"
    ]
    
    for message in messages:
        result = analyze_message(message)
        assert result['classification'] in ["LOW RISK", "MEDIUM RISK", "HIGH RISK"]


def test_color_mapping():
    """Test that color matches classification"""
    # High risk
    high_msg = "URGENT: Verify SSN https://bit.ly/scam account suspended"
    high_result = analyze_message(high_msg)
    assert high_result['color'] == "red"
    
    # Medium risk
    medium_msg = "Dear Customer, verify your account within 24 hours"
    medium_result = analyze_message(medium_msg)
    assert medium_result['color'] == "orange"
    
    # Low risk
    low_msg = "Meeting at 2pm tomorrow"
    low_result = analyze_message(low_msg)
    assert low_result['color'] == "green"


def test_patterns_is_list():
    """Test that patterns_detected is a list"""
    message = "Test message"
    result = analyze_message(message)
    
    assert isinstance(result['patterns_detected'], list)


# ==============================================================================
# REAL-WORLD PHISHING EXAMPLES
# ==============================================================================

def test_paypal_phishing():
    """Test realistic PayPal phishing attempt"""
    message = """
    Dear PayPal User,
    
    We detected unusual activity on your account. Your account has been 
    temporarily suspended. Please verify your identity immediately:
    
    https://paypal-secure.tk/verify
    
    Failure to verify within 24 hours will result in permanent account closure.
    """
    result = analyze_message(message)
    
    assert result['classification'] == "HIGH RISK"
    assert result['risk_score'] >= 60


def test_delivery_scam():
    """Test package delivery scam"""
    message = "Your package could not be delivered. Update your address and payment: http://usps-redelivery.ml/track"
    result = analyze_message(message)
    
    assert result['classification'] in ["MEDIUM RISK", "HIGH RISK"]
    assert result['risk_score'] >= 30


def test_tax_refund_scam():
    """Test IRS/tax refund scam"""
    message = "IRS Notice: You have a pending tax refund of $842. Claim now: http://irs-refund.ga/claim"
    result = analyze_message(message)
    
    assert result['classification'] == "HIGH RISK"


def test_bank_alert_phishing():
    """Test fake bank security alert"""
    message = """
    SECURITY ALERT: Chase Bank
    
    Unauthorized login attempt detected from California.
    Verify your account now: https://chase-security.tk
    
    Click here to secure your account.
    """
    result = analyze_message(message)
    
    assert result['classification'] == "HIGH RISK"


# ==============================================================================
# LEGITIMATE MESSAGE TESTS (Should be LOW RISK)
# ==============================================================================

def test_legitimate_amazon_confirmation():
    """Test real Amazon order confirmation format"""
    message = """
    Hello John,
    
    Your order #123-4567890-1234567 has been shipped.
    
    Track your package: amazon.com/orders
    
    Expected delivery: Friday, May 3
    """
    result = analyze_message(message)
    
    assert result['classification'] == "LOW RISK"


def test_legitimate_calendar_invite():
    """Test calendar invitation"""
    message = "Meeting: Q2 Planning Session - Tuesday 2pm EST - Conference Room A"
    result = analyze_message(message)
    
    assert result['classification'] == "LOW RISK"


def test_legitimate_receipt():
    """Test purchase receipt"""
    message = "Thank you for your purchase. Receipt for $24.99 at Starbucks. Order #12345."
    result = analyze_message(message)
    
    assert result['classification'] == "LOW RISK"


# ==============================================================================
# RUN ALL TESTS
# ==============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

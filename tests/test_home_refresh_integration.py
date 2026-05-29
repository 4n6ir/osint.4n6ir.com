import json
import os
import time

import pytest

# pyright: reportPrivateUsage=false, reportGeneralTypeIssues=false


os.environ.setdefault('AWS_EC2_METADATA_DISABLED', 'true')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
os.environ.setdefault('AWS_REGION', 'us-east-1')

from home import home

try:
    import playwright.sync_api as playwright
except ImportError:
    playwright = None
    pytestmark = pytest.mark.skip(reason='Playwright is not installed')


def _empty_sections_payload():
    return {
        'suspect': {
            'openSourceIntelligence': [],
            'domainsMonitorSubscription': [],
        },
        'newRegistrations': {
            'daily': [],
            'weekly': [],
            'monthly': [],
        },
        'expiredRegistrations': {
            'daily': [],
            'weekly': [],
            'monthly': [],
        },
    }


def test_back_then_refresh_stays_on_home_view(monkeypatch):
    api_url = 'https://api.test/home'
    monkeypatch.setattr(home, 'API_ENDPOINT', api_url)
    html = home.render_form(
        'token',
        {'email': 'user@example.com', 'region': 'us-east-1'},
        ['example.com'],
        {'example'},
    )

    with playwright.sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=True)
        except playwright.Error as exc:  # pragma: no cover
            pytest.skip(f'Chromium is not available for Playwright: {exc}')

        context = browser.new_context()
        page = context.new_page()

        def handle_route(route):
            request = route.request
            if request.url != api_url:
                route.continue_()
                return

            if request.method == 'POST':
                payload = json.loads(request.post_data or '{}')
                action = payload.get('action')
                if action == 'GetDomainSections':
                    route.fulfill(
                        status=200,
                        headers={'Content-Type': 'application/json'},
                        body=json.dumps(
                            {
                                'sections': _empty_sections_payload(),
                                'permutations': 2,
                            }
                        ),
                    )
                    return

                if action == 'GetDomainPermutations':
                    route.fulfill(
                        status=200,
                        headers={'Content-Type': 'application/json'},
                        body=json.dumps({'permutations': ['example1.com', 'example2.com']}),
                    )
                    return

                route.fulfill(status=500, body='unexpected POST action')
                return

            if request.method == 'GET':
                # Delay home reload so refresh can be clicked while back navigation is in-flight.
                time.sleep(0.2)
                route.fulfill(
                    status=200,
                    headers={'Content-Type': 'text/html; charset=utf-8'},
                    body=html,
                )
                return

            route.fulfill(status=405, body='method not allowed')

        page.route('**/*', handle_route)
        page.set_content(html)

        page.click("a[data-domain='example.com']")
        page.wait_for_selector('text=Suspect Domains')

        page.click("a:has-text('Back')")
        page.click('button.refresh-button')

        page.wait_for_selector('#home-form')
        expect_domain_header = page.locator("p:has-text('Domain:')")
        assert expect_domain_header.count() == 0

        context.close()
        browser.close()


def test_refresh_stays_on_domain_permutations_view(monkeypatch):
    api_url = 'https://api.test/home'
    monkeypatch.setattr(home, 'API_ENDPOINT', api_url)
    html = home.render_form(
        'token',
        {'email': 'user@example.com', 'region': 'us-east-1'},
        ['example.com'],
        {'example'},
    )

    with playwright.sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=True)
        except playwright.Error as exc:  # pragma: no cover
            pytest.skip(f'Chromium is not available for Playwright: {exc}')

        context = browser.new_context()
        page = context.new_page()

        def handle_route(route):
            request = route.request
            if request.url != api_url:
                route.continue_()
                return

            if request.method == 'POST':
                payload = json.loads(request.post_data or '{}')
                action = payload.get('action')
                if action == 'GetDomainSections':
                    route.fulfill(
                        status=200,
                        headers={'Content-Type': 'application/json'},
                        body=json.dumps(
                            {
                                'sections': _empty_sections_payload(),
                                'permutations': 2,
                            }
                        ),
                    )
                    return

                if action == 'GetDomainPermutations':
                    route.fulfill(
                        status=200,
                        headers={'Content-Type': 'application/json'},
                        body=json.dumps({'permutations': ['example1.com', 'example2.com']}),
                    )
                    return

                route.fulfill(status=500, body='unexpected POST action')
                return

            if request.method == 'GET':
                route.fulfill(
                    status=200,
                    headers={'Content-Type': 'text/html; charset=utf-8'},
                    body=html,
                )
                return

            route.fulfill(status=405, body='method not allowed')

        page.route('**/*', handle_route)
        page.set_content(html)

        page.click("a[data-domain='example.com']")
        page.wait_for_selector('text=Suspect Domains')
        page.click('button.refresh-button')
        page.wait_for_selector('text=Suspect Domains')

        permutations_link = page.locator("p:has-text('Permutations:') a.inline-link")
        permutations_link.click()
        page.wait_for_selector("h3:has-text('Permutations')")
        page.click('button.refresh-button')
        page.wait_for_selector("h3:has-text('Permutations')")

        page.click("a:has-text('Back')")
        page.wait_for_selector('text=Suspect Domains')

        domains_link = page.locator("p:has-text('Domains:') a.inline-link")
        domains_link.click()
        page.wait_for_selector("h3:has-text('Domains')")
        page.click('button.refresh-button')
        page.wait_for_selector("h3:has-text('Domains')")

        context.close()
        browser.close()
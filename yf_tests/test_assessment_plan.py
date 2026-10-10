import unittest

class AssessmentPlanTests(unittest.TestCase):
    def policy(self):
        return {'targets':['example.test','192.0.2.0/24'], 'exclude':['192.0.2.9'], 'allowed_tests':['http_baseline','port_scan'], 'requests_per_second':2}

    def test_exact_domain_allowed(self):
        from yf_tools.assessment_plan import build_plan
        self.assertEqual(len(build_plan(self.policy(),'https://example.test')['tasks']),2)

    def test_subdomain_not_implicitly_allowed(self):
        from yf_tools.assessment_plan import build_plan, PlanError
        with self.assertRaises(PlanError): build_plan(self.policy(),'https://x.example.test')

    def test_exclusion_wins(self):
        from yf_tools.assessment_plan import build_plan, PlanError
        with self.assertRaises(PlanError): build_plan(self.policy(),'192.0.2.9')

    def test_cidr_matches(self):
        from yf_tools.assessment_plan import build_plan
        self.assertEqual(build_plan(self.policy(),'192.0.2.8')['host'],'192.0.2.8')

    def test_unknown_test_rejected(self):
        from yf_tools.assessment_plan import build_plan, PlanError
        p=self.policy();p['allowed_tests']=['whatever']
        with self.assertRaises(PlanError): build_plan(p,'example.test')

    def test_url_credentials_rejected(self):
        from yf_tools.assessment_plan import build_plan, PlanError
        with self.assertRaises(PlanError): build_plan(self.policy(),'https://secret@example.test')

    def test_invalid_rate_rejected(self):
        from yf_tools.assessment_plan import build_plan, PlanError
        p=self.policy();p['requests_per_second']=0
        with self.assertRaises(PlanError): build_plan(p,'example.test')

    def test_not_an_executor(self):
        from yf_tools.assessment_plan import build_plan
        self.assertFalse(build_plan(self.policy(),'example.test')['executed'])

import json
import unittest

import scan_report


class ScanReportTests(unittest.TestCase):
    def test_aggregates_latencies_by_client_without_echoing_private_fields(self):
        logs = []
        for n in range(1, 21):
            logs.append('journal prefix ' + json.dumps({
                'event': 'scan_complete', 'client_id': 'mx-one', 'scan_ms': n,
                'queue_ms': 0, 'score': -1.2, 'action': 'no action',
                'symbols': ['BAYES_HAM', 'private-symbol'],
                'bayes_ham_probability': 99.99, 'bayes_spam_probability': None,
                'message_id': 'private-id', 'subject': 'private-subject',
                'token': 'private-token', 'body': 'private-body'}))
        result = scan_report.report(logs)
        group = result['clients']['mx-one']
        self.assertEqual(group['events']['scan_complete'], 20)
        self.assertEqual(group['metrics']['scan_ms'], {'samples': 20, 'p50': 10, 'p95': 19, 'max': 20})
        self.assertEqual(group['metrics']['bayes_ham_probability'],
                         {'samples': 20, 'p50': 99.99, 'p95': 99.99, 'max': 99.99})
        self.assertEqual(group['metrics']['bayes_spam_probability'], {'samples': 0})
        self.assertEqual(group['bayes_symbols'], {'BAYES_HAM': 20})
        self.assertNotIn('private-', json.dumps(result))

    def test_reports_only_allowlisted_antivirus_symbols(self):
        result = scan_report.report(map(json.dumps, [
            {'event': 'scan_complete', 'client_id': 'enhance-postfix',
             'symbols': ['CLAM_VIRUS', 'BAYES_SPAM', 'Trojan.Private.Name']},
            {'event': 'scan_complete', 'client_id': 'enhance-postfix',
             'symbols': ['CLAM_VIRUS_FAIL', 'CLAM_VIRUS_ENCRYPTED', 'private-symbol']},
            {'event': 'scan_complete', 'client_id': 'enhance-postfix',
             'symbols': ['CLAM_VIRUS_MACRO', 'CLAM_VIRUS']}]))
        group = result['clients']['enhance-postfix']
        self.assertEqual(group['antivirus_symbols'], {
            'CLAM_VIRUS': 2, 'CLAM_VIRUS_FAIL': 1,
            'CLAM_VIRUS_ENCRYPTED': 1, 'CLAM_VIRUS_MACRO': 1})
        rendered = json.dumps(result)
        self.assertNotIn('Trojan.Private.Name', rendered)
        self.assertNotIn('private-symbol', rendered)

    def test_failures_are_not_successful_scans_and_unknown_actions_are_redacted(self):
        result = scan_report.report(map(json.dumps, [
            {'event': 'scan_failed', 'client_id': 'mx-two', 'score': 99, 'scan_ms': 9},
            {'event': 'scan_complete', 'client_id': 'mx-two', 'action': 'secret action',
             'bayes_spam_probability': 101},
            {'event': 'upload_skipped', 'client_id': 'mx-two', 'latency_ms': 1000}]))
        group = result['clients']['mx-two']
        self.assertEqual(group['metrics']['scan_ms'], {'samples': 0})
        self.assertEqual(group['metrics']['score'], {'samples': 0})
        self.assertEqual(group['metrics']['bayes_spam_probability'], {'samples': 0})
        self.assertEqual(group['recommended_actions'], {'other': 1})
        self.assertEqual(group['metrics']['latency_ms']['max'], 1000)
        self.assertNotIn('secret', json.dumps(result))

    def test_summarizes_spfbl_and_autolearn_states_with_allowlisted_values(self):
        result = scan_report.report(map(json.dumps, [
            {'event': 'scan_complete', 'client_id': 'mx-pilot',
             'autolearn_profile_selected': True, 'autolearn_eligibility': 'eligible',
             'spfbl_ticket_status': 'ticket_present', 'spfbl_feedback': 'below_spam_threshold',
             'spfbl_feedback_policy': None},
            {'event': 'scan_complete', 'client_id': 'mx-pilot',
             'autolearn_profile_selected': False,
             'autolearn_eligibility': 'authenticated,non_inbound_smtp_port',
             'spfbl_ticket_status': 'ticket_missing', 'spfbl_feedback': 'accepted',
             'spfbl_feedback_policy': 'bayes_spam_probability_95'},
            {'event': 'scan_complete', 'client_id': 'mx-pilot',
             'autolearn_profile_selected': True, 'autolearn_eligibility': 'secret@example.invalid',
             'spfbl_ticket_status': 'secret-token', 'spfbl_feedback': 'secret@example.invalid',
             'spfbl_feedback_policy': 'secret@example.invalid'},
            {'event': 'scan_complete', 'client_id': 'mx-pilot'},
        ]))
        group = result['clients']['mx-pilot']
        self.assertEqual(group['autolearn']['profile_selected'],
                         {'selected': 2, 'not_selected': 1, 'legacy_unknown': 1})
        self.assertEqual(group['autolearn']['eligibility'], {
            'eligible': 1, 'authenticated': 1, 'non_inbound_smtp_port': 1,
            'other': 1, 'legacy_unknown': 1})
        self.assertEqual(group['spfbl']['ticket_status'], {
            'ticket_present': 1, 'ticket_missing': 1, 'other': 1, 'legacy_unknown': 1})
        self.assertEqual(group['spfbl']['feedback'], {
            'below_spam_threshold': 1, 'accepted': 1, 'other': 1, 'legacy_unknown': 1})
        self.assertEqual(group['spfbl']['policy'], {
            'none': 1, 'bayes_spam_probability_95': 1, 'other': 1, 'legacy_unknown': 1})
        self.assertNotIn('secret@example.invalid', json.dumps(result))
        self.assertNotIn('secret-token', json.dumps(result))

    def test_tolerates_journal_noise_invalid_fields_and_bounds_metric_memory(self):
        logs = ['service started', '{}', '[]', '{broken', '{"event":[]}']
        for n in range(6):
            logs.append(json.dumps({'event': 'scan_complete', 'client_id': 'mx-three', 'scan_ms': n}))
        logs.append(json.dumps({'event': 'scan_complete', 'client_id': 'mx-three', 'scan_ms': True, 'score': float('nan')}))
        result = scan_report.report(logs, sample_limit=3)
        group = result['clients']['mx-three']
        self.assertEqual(result['ignored_lines'], 5)
        self.assertEqual(group['events']['scan_complete'], 7)
        self.assertEqual(group['metrics']['scan_ms'], {'samples': 3, 'p50': 4, 'p95': 5, 'max': 5})
        self.assertEqual(group['metrics']['score'], {'samples': 0})
        json.dumps(result, allow_nan=False)

    def test_unattributed_denials_are_counted_without_echoing_invalid_client(self):
        result = scan_report.report([json.dumps({'event': 'request_denied', 'client_id': 'secret@example.com'})])
        self.assertEqual(result['clients']['unattributed']['events'], {'request_denied': 1})
        self.assertNotIn('secret@example.com', json.dumps(result))

    def test_aggregates_only_allowlisted_failure_reasons(self):
        result = scan_report.report(map(json.dumps, [
            {'event': 'request_dropped', 'client_id': 'enhance-postfix',
             'reason': 'invalid_or_incomplete_body', 'message_id': 'private-id'},
            {'event': 'upload_skipped', 'client_id': 'enhance-postfix',
             'reason': 'message_too_large', 'bytes': 26279936},
            {'event': 'upload_skipped', 'client_id': 'enhance-postfix',
             'reason': 'secret@example.com', 'subject': 'private-subject'},
        ]))
        outcomes = result['clients']['enhance-postfix']['outcomes']
        self.assertEqual(outcomes, {
            'request_dropped': {'invalid_or_incomplete_body': 1},
            'upload_skipped': {'message_too_large': 1, 'other': 1},
        })
        rendered = json.dumps(result)
        self.assertNotIn('private-id', rendered)
        self.assertNotIn('private-subject', rendered)
        self.assertNotIn('secret@example.com', rendered)

    def test_legacy_intake_and_queue_timing_is_not_reported_as_pure_queue_wait(self):
        result = scan_report.report(map(json.dumps, [
            {'event': 'scan_complete', 'client_id': 'mx-four', 'queue_ms': 1443},
            {'event': 'message_queued', 'client_id': 'mx-four', 'intake_ms': 1000, 'timing_version': 2},
            {'event': 'scan_complete', 'client_id': 'mx-four', 'queue_ms': 2, 'timing_version': 2}]))
        metrics = result['clients']['mx-four']['metrics']
        self.assertEqual(metrics['queue_ms']['max'], 2)
        self.assertEqual(metrics['queue_ms']['samples'], 1)
        self.assertEqual(metrics['legacy_intake_and_queue_ms']['max'], 1443)
        self.assertEqual(metrics['intake_ms']['max'], 1000)


if __name__ == '__main__':
    unittest.main()

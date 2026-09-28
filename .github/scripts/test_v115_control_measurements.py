"""Synthetic control ledgers; no binaries, timing, dispatch or authentication."""
from copy import deepcopy
from datetime import date
import hashlib
import unittest

from v115_control_measurements import (VARIANTS, dispatch_day, remaining_seconds,
                                      process_plan, qualify_measurement)
from v115_evidence import DEMOTED, FEATURE_LEGS, TELEMETRY, required_bounds
from v115_gate_rules import CONTEXT, LEAKY, Measurement, control_job

CPU='AMD EPYC 9V74 80-Core Processor'
BINARY='a'*64


def stdout(names, value='0.10000'):
    return ''.join('bench '+name+' seeded with 0x1234\nbench '+name+
                   ' ... : n == 0.099M, max t = -1.50000, max tau = '+
                   ('1.00001' if name=='negative_control' else value)+', (test)\n' for name in names).encode()


def fixture(index=0, leg='default'):
    processes=process_plan(index,leg);files={}
    for row in processes:
        names=(list(required_bounds(leg,CPU))+[TELEMETRY,'negative_control'] if row['role']=='full'
               else [row['target']] if row['role']=='target' else ['negative_control'])
        data=stdout(names,'0.30000' if row['variant'] in LEAKY else '0.10000')
        row.update(status='completed',returncode=0,binary_sha256_before=BINARY,binary_sha256_after=BINARY,
                   stdout_sha256=hashlib.sha256(data).hexdigest())
        files[row['stdout_path']]=data
    return processes,files


def qualify(processes,files,variant='filtered',target=DEMOTED[0],**extra):
    return qualify_measurement(dispatch_index=0,feature_leg='default',target=target,variant=variant,
                               processes=processes,files=files,cpu=CPU,binary_sha256=BINARY,**extra)


def replace_output(row, files, data):
    files[row['stdout_path']]=data;row['stdout_sha256']=hashlib.sha256(data).hexdigest()


class PlanTests(unittest.TestCase):
    def test_twelve_dispatch_dates_follow_fixed_offsets(self):
        start=date(2030,1,1)
        self.assertEqual([(dispatch_day(start,i)-start).days for i in range(12)],
                         [1,4,8,11,15,18,22,25,29,32,36,39])
        for index in (-1,12,True,1.0):
            with self.subTest(index=index),self.assertRaises(ValueError):dispatch_day(start,index)

    def test_fixed_245_process_inventory_and_rotated_order_all_legs(self):
        for leg in FEATURE_LEGS:
            for index in range(12):
                rows=process_plan(index,leg)
                self.assertEqual(len(rows),245)
                self.assertEqual([r['role'] for r in rows[:5]],['full']*5)
                self.assertEqual([r['target'] for r in rows[5::60]],list(DEMOTED[index%4:]+DEMOTED[:index%4]))
                self.assertEqual(len({r['stdout_path'] for r in rows}),245)
                self.assertEqual([r['sequence'] for r in rows],list(range(245)))
                for target in DEMOTED:
                    for number in range(1,6):
                        block=[r for r in rows if r['target']==target and r['pass_number']==number]
                        offset=number-1
                        self.assertEqual([r['variant'] for r in block[::2]],list(VARIANTS[offset:]+VARIANTS[:offset]))
                        self.assertEqual([r['role'] for r in block],['target','negative_control']*6)
                self.assertTrue(all(r['sample_budget']==100000 for r in rows))
                self.assertTrue(all(r['binary_key']=='baseline' for r in rows if r['variant'] in ('full','filtered')))

    def test_setup_time_counts_against_whole_job_budget(self):
        self.assertEqual(remaining_seconds(100,100),5275)
        self.assertEqual(remaining_seconds(100,5200),175)
        for a,b in ((100,5375),(100,99),(True,100),(0,float('nan')),(0,float('inf'))):
            with self.subTest(a=a,b=b),self.assertRaises(ValueError):remaining_seconds(a,b)


class MeasurementTests(unittest.TestCase):
    def test_complete_full_and_filtered_measurements_preserve_signed_values(self):
        processes,files=fixture()
        for variant in ('full',)+VARIANTS:
            r=qualify(processes,files,variant)
            self.assertTrue(r['measurement_complete'],r['issues'])
            self.assertEqual(len(r['tau']),5);self.assertEqual(len(r['negative_control']),5)
            self.assertTrue(r['authentication_required'])
            self.assertNotIn('qualified',r)
        row=processes[5];replace_output(row,files,stdout([row['target']],'-0.12345'))
        self.assertEqual(qualify(processes,files)['tau'][0],'-0.12345')

    def test_later_timeout_preserves_completed_measurements_and_escape(self):
        processes,files=fixture()
        for row in processes:
            if row['target']==DEMOTED[0] and row['variant']=='modest-left' and row['role']=='target':
                replace_output(row,files,stdout([row['target']],'0.10000'))
        # First target's last negative-control process times out after other
        # variants completed all five passes. Nothing is retried or replaced.
        processes=processes[:65];processes[-1].update(status='timeout',returncode=None)
        measurements={}
        for variant in CONTEXT+LEAKY:
            r=qualify(processes,files,variant)
            # This test supplies synthetic provenance; real use still owes the
            # independent authenticated binder called out by the helper.
            measurements[variant]=Measurement(r['tau'] or [],r['negative_control'] or [],r['measurement_complete'])
        self.assertTrue(measurements['full'].qualified)
        self.assertTrue(measurements['modest-left'].qualified)
        self.assertFalse(measurements['modest-right'].qualified)
        self.assertEqual(control_job('0.20',measurements)['status'],'rejected')

    def test_usable_baseline_breach_remains_when_other_measurements_never_start(self):
        processes,files=fixture()
        for row in processes[:5]:
            data=files[row['stdout_path']].replace(b'max tau = 0.10000',b'max tau = 0.25000')
            replace_output(row,files,data)
        r=qualify(processes[:5],files,'full')
        self.assertTrue(r['measurement_complete'])
        result=control_job('0.20',{'full':Measurement(r['tau'],r['negative_control'],True)})
        self.assertEqual(result['status'],'rejected')
        self.assertFalse(qualify(processes[:5],files)['measurement_complete'])

    def test_wrong_single_process_inventory_cannot_hide_in_combined_pass(self):
        processes,files=fixture();target,negative=processes[5:7]
        a,b=files[target['stdout_path']],files[negative['stdout_path']]
        replace_output(target,files,b);replace_output(negative,files,a)
        r=qualify(processes,files)
        self.assertFalse(r['measurement_complete'])
        self.assertTrue(any(x.startswith('wrong-process-target-inventory:') for x in r['issues']))

    def test_filtered_collisions_duplicates_nonfinite_and_liveness_fail(self):
        for mutation in ('collision','duplicate','nan','liveness'):
            processes,files=fixture();row=processes[5]
            if mutation=='collision':data=files[row['stdout_path']]+stdout(['prefix_'+row['target']])
            elif mutation=='duplicate':data=files[row['stdout_path']]*2
            elif mutation=='nan':data=stdout([row['target']],'NaN')
            else:
                row=processes[6];data=stdout(['negative_control']).replace(b'1.00001',b'1.00000')
            replace_output(row,files,data)
            with self.subTest(mutation=mutation):self.assertFalse(qualify(processes,files)['measurement_complete'])

    def test_failed_process_binary_drift_or_output_tampering_invalidates_measurement(self):
        for mutation in ('exit','bool-exit','binary','bytes','missing'):
            processes,files=fixture();row=processes[5]
            if mutation=='exit':row['returncode']=1
            elif mutation=='bool-exit':row['returncode']=False
            elif mutation=='binary':row['binary_sha256_after']='b'*64
            elif mutation=='bytes':files[row['stdout_path']]+=b'drift'
            else:files.pop(row['stdout_path'])
            with self.subTest(mutation=mutation):self.assertFalse(qualify(processes,files)['measurement_complete'])

    def test_reordered_retried_skipped_or_wrong_budget_processes_refuse_ledger(self):
        for mutation in ('reorder','retry','skip','budget','bool-id','output-path'):
            processes,files=fixture()
            if mutation=='reorder':processes[5],processes[6]=processes[6],processes[5]
            elif mutation=='retry':processes.append(deepcopy(processes[-1]))
            elif mutation=='skip':processes.pop(10)
            elif mutation=='budget':processes[5]['sample_budget']=10000
            elif mutation=='bool-id':processes[0]['sequence']=False
            else:processes[5]['stdout_path']=processes[6]['stdout_path']
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):qualify(processes,files)

    def test_full_baseline_requires_all_production_targets_and_keeps_alarms(self):
        processes,files=fixture()
        for row in processes[:5]:
            data=files[row['stdout_path']].replace(b'bench ct_mul_g ',b'bench missing_ct_mul_g ')
            replace_output(row,files,data)
        self.assertFalse(qualify(processes,files,'full')['measurement_complete'])
        processes,files=fixture()
        for row in processes[:5]:
            data=files[row['stdout_path']].replace(b'max tau = 0.10000',b'max tau = 0.60000')
            replace_output(row,files,data)
        r=qualify(processes,files,'full')
        self.assertTrue(r['measurement_complete'])
        self.assertIn('ct_mul_g',r['output']['existing_gate_breaches'])


if __name__=='__main__':unittest.main()

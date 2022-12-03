package analysis.exercise1;

import javax.crypto.Cipher;

import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.internal.JAssignStmt;
import analysis.AbstractAnalysis;
import analysis.VulnerabilityReporter;
import soot.Body;
import soot.Unit;
import soot.jimple.internal.JStaticInvokeExpr;

public class MisuseAnalysis extends AbstractAnalysis{
	public MisuseAnalysis(Body body, VulnerabilityReporter reporter) {
		super(body, reporter);
	}
	
	@Override
	protected void flowThrough(Unit unit) {
		// TODO: Implement your analysis here.
//        if(unit instanceof JAssignStmt){
//			if (((JAssignStmt)unit).getRightOp() instanceof JStaticInvokeExpr)
//			{
//				JStaticInvokeExpr expr = (JStaticInvokeExpr)((JAssignStmt)unit).getRightOp();
//				if (expr.getMethodRef().getDeclaringClass().getName().equals("javax.crypto.Cipher")) {
//					if (expr.getArgs().get(0).toString().equals("\"AES\""))
//					reporter.reportVulnerability(method.getSignature(), unit);
//				}
//			}
//        }
		if(unit instanceof InvokeStmt){
			InvokeStmt invoke = (InvokeStmt) unit;
			InvokeExpr expression = invoke.getInvokeExpr();
			String invokeClass = expression.getMethod().getDeclaringClass().getName();
			if (invokeClass.equals("javax.crypto.Cipher")) {
				String argument = expression.getArgs().get(0).toString();
				if (argument.equals("\"AES\""))
					reporter.reportVulnerability(method.getSignature(), unit);
			}
		}
	}
}

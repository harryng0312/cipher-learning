package org.hikarikyou.demo.main;

public class TestThread {

    public static void main(String[] args){
        Runnable runnable = new Runnable() {
            public void run() {
                int i = 0;
//                while(i< 10){
//                    i++;
//                }
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                System.out.println("+++");
            }
        };
        Thread t = new Thread(runnable);
        t.start();
        try {
            t.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        System.out.println("====");
//        t.start();
//        try {
//            t.join();
//        } catch (InterruptedException e) {
//            e.printStackTrace();
//        }
//        new Thread(runnable).start();
//        new Thread(runnable).start();
//        new Thread(runnable).start();
//        new Thread(runnable).start();
//        new Thread(runnable).start();

//        new Thread(runnable).start();
//        new Thread(runnable).start();
//        new Thread(runnable).start();
//        new Thread(runnable).start();
//        new Thread(runnable).start();
//        new Thread(runnable).start();
    }
}

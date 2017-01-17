package uk.org.lidalia.crypto

import spock.lang.Specification

abstract class EqualsAndHashcodeTests<T> extends Specification {

    abstract T getInstance1()
    abstract T getEqualToInstance1()
    abstract T getInstance2()
    abstract T getEqualToInstance2()

    def 'hashCode is constant'() {
        expect:
            getInstance1().hashCode() == getInstance1().hashCode()
            getEqualToInstance1().hashCode() == getEqualToInstance1().hashCode()
            getInstance2().hashCode() == getInstance2().hashCode()
            getEqualToInstance2().hashCode() == getEqualToInstance2().hashCode()
    }

    def 'hashCode is same for equal instances'() {
        expect:
            getInstance1().hashCode() == getEqualToInstance1().hashCode()
            getInstance2().hashCode() == getEqualToInstance2().hashCode()
    }

    def 'hashCode is different in unequal instance'() {
        expect:
            getInstance1().hashCode() != getInstance2().hashCode()
            getInstance1().hashCode() != getEqualToInstance2().hashCode()
            getEqualToInstance1().hashCode() != getInstance2().hashCode()
            getEqualToInstance1().hashCode() != getEqualToInstance2().hashCode()
    }

    def 'equals is reflexive'() {
        expect:
            getInstance1() == getInstance1()
            getEqualToInstance1() == getEqualToInstance1()
            getInstance2() == getInstance2()
            getEqualToInstance2() == getEqualToInstance2()
    }

    def 'equals is symmetric'() {
        expect:
            getInstance1() == getEqualToInstance1()
            getEqualToInstance1() == getInstance1()
            getInstance2() == getEqualToInstance2()
            getEqualToInstance2() == getInstance2()
    }

    def 'different instances are not equal'() {
        expect:
            getInstance1() != getInstance2()
            getInstance1() != getEqualToInstance2()
            getInstance2() != getInstance1()
            getInstance2() != getEqualToInstance1()
            getEqualToInstance1() != getInstance2()
            getEqualToInstance1() != getEqualToInstance2()
            getEqualToInstance2() != getInstance1()
            getEqualToInstance2() != getEqualToInstance1()
    }
}

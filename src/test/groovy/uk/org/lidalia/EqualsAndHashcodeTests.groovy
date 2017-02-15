package uk.org.lidalia

import spock.lang.Specification

abstract class EqualsAndHashcodeTests<T> extends Specification {

    abstract T getInstance1A()
    abstract T getInstance1B()
    abstract T getInstance1C()
    
    abstract T getInstance2A()
    abstract T getInstance2B()
    abstract T getInstance2C()

    def 'hashCode is constant'() {
        expect:
            instance1A.hashCode() == instance1A.hashCode()
            instance1B.hashCode() == instance1B.hashCode()
            instance1C.hashCode() == instance1C.hashCode()
            instance2A.hashCode() == instance2A.hashCode()
            instance2B.hashCode() == instance2B.hashCode()
            instance2C.hashCode() == instance2C.hashCode()
    }

    def 'hashCode is same for equal instances'() {
        expect:
            instance1A.hashCode() == instance1B.hashCode()
            instance1A.hashCode() == instance1C.hashCode()
            instance1A.hashCode() == instance1C.hashCode()
        
            instance2A.hashCode() == instance2B.hashCode()
            instance2A.hashCode() == instance2C.hashCode()
            instance2A.hashCode() == instance2C.hashCode()
    }

    def 'hashCode is different in unequal instance'() {
        expect:
            instance1A.hashCode() != instance2A.hashCode()
            instance1A.hashCode() != instance2B.hashCode()
            instance1A.hashCode() != instance2C.hashCode()
        
            instance1B.hashCode() != instance2A.hashCode()
            instance1B.hashCode() != instance2B.hashCode()
            instance1B.hashCode() != instance2C.hashCode()

            instance1C.hashCode() != instance2A.hashCode()
            instance1C.hashCode() != instance2B.hashCode()
            instance1C.hashCode() != instance2C.hashCode()
    }

    def 'equals is reflexive'() {
        expect:
            instance1A == instance1A
            instance1B == instance1B
            instance1C == instance1C
            instance2A == instance2A
            instance2B == instance2B
            instance2C == instance2C
    }

    def 'equals is symmetric and transitive when equal'() {
        expect:
            instance1A == instance1B
            instance1B == instance1C
            instance1C == instance1A

            instance1B == instance1A
            instance1A == instance1C
            instance1C == instance1B

            instance2A == instance2B
            instance2B == instance2C
            instance2C == instance2A

            instance2B == instance2A
            instance2A == instance2C
            instance2C == instance2B
    }

    def 'equals is symmetric when false'() {
        expect:
            instance1A != instance2A
            instance1A != instance2B
            instance1A != instance2C

            instance1B != instance2A
            instance1B != instance2B
            instance1B != instance2C

            instance1C != instance2A
            instance1C != instance2B
            instance1C != instance2C

            instance2A != instance1A
            instance2A != instance1B
            instance2A != instance1C

            instance2B != instance1A
            instance2B != instance1B
            instance2B != instance1C

            instance2C != instance1A
            instance2C != instance1B
            instance2C != instance1C
    }
}
